"""Binding a phone to a user.

An admin issues a one-time enrolment code out of band. The phone exchanges it
for an attestation challenge, generates a key inside the Keystore over that
challenge, and posts the resulting certificate chain back. The server checks
that the chain says what it needs to say, that the challenge in the chain is
the one it issued, and that Play Integrity is happy with the app. Only then
does a device row appear.

The challenge lives in memory with a short lifetime. It is single use: a chain
can only be presented once, so a captured chain cannot be replayed onto a
second enrolment.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass

from app.core.attestation import (
    decode_integrity_payload,
    evaluate_play_integrity,
    verify_key_attestation,
)
from app.core.config import Settings
from app.core.errors import AuditEvent, AuthenticationError, Conflict
from app.db.repositories.devices import DeviceRepository, EnrollmentRepository
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService, IssuedTokens

CHALLENGE_TTL_SECONDS = 300


@dataclass
class _Challenge:
    value: bytes
    user_hint: str
    expires_at: float


class ChallengeStore:
    """Deliberately in process.

    The challenge is worthless to anyone who does not already hold the
    enrolment code, it lives for five minutes, and enrolment is rare. Putting
    it in the database would add a write path that exists only to serve an
    attacker's replay attempt.
    """

    def __init__(self) -> None:
        self._items: dict[str, _Challenge] = {}

    def issue(self, code_hash: bytes) -> bytes:
        self._sweep()
        value = secrets.token_bytes(32)
        self._items[code_hash.hex()] = _Challenge(
            value=value, user_hint="", expires_at=time.time() + CHALLENGE_TTL_SECONDS
        )
        return value

    def take(self, code_hash: bytes) -> bytes | None:
        self._sweep()
        item = self._items.pop(code_hash.hex(), None)
        return item.value if item else None

    def _sweep(self) -> None:
        now = time.time()
        for key in [k for k, v in self._items.items() if v.expires_at < now]:
            self._items.pop(key, None)


class EnrollmentService:
    def __init__(
        self,
        *,
        enrollments: EnrollmentRepository,
        devices: DeviceRepository,
        auth: AuthService,
        audit: AuditService,
        challenges: ChallengeStore,
        settings: Settings,
    ) -> None:
        self._enrollments = enrollments
        self._devices = devices
        self._auth = auth
        self._audit = audit
        self._challenges = challenges
        self._settings = settings

    @staticmethod
    def hash_code(code: str) -> bytes:
        return hashlib.sha256(code.strip().encode("utf-8")).digest()

    def issue_challenge(self, enrollment_code: str) -> tuple[str, int]:
        challenge = self._challenges.issue(self.hash_code(enrollment_code))
        return base64.b64encode(challenge).decode("ascii"), CHALLENGE_TTL_SECONDS

    async def enroll(
        self,
        *,
        enrollment_code: str,
        label: str,
        device_public_key_b64: str,
        attestation_chain: list[str],
        play_integrity_token: str,
        presented_challenge_b64: str,
        app_version: str | None,
        client_ip: str | None,
    ) -> tuple[uuid.UUID, str, IssuedTokens]:
        code_hash = self.hash_code(enrollment_code)
        expected = self._challenges.take(code_hash)
        presented = base64.b64decode(presented_challenge_b64, validate=True)

        if expected is None or not secrets.compare_digest(expected, presented):
            await self._audit.failure(
                AuditEvent.DEVICE_ENROLL_DENIED,
                actor_type="anonymous",
                client_ip=client_ip,
                detail={"reason": "challenge_missing_or_stale"},
            )
            raise AuthenticationError("challenge_mismatch")

        claimed = await self._enrollments.claim(code_hash)
        if claimed is None:
            await self._audit.failure(
                AuditEvent.DEVICE_ENROLL_DENIED,
                actor_type="anonymous",
                client_ip=client_ip,
                detail={"reason": "enrollment_code_invalid_or_used"},
            )
            raise AuthenticationError("enrollment_code_invalid")

        key_verdict = verify_key_attestation(attestation_chain, presented)
        integrity_ok, integrity_detail = evaluate_play_integrity(
            decode_integrity_payload(play_integrity_token),
            expected_package=self._settings.play_integrity_package_name,
            expected_cert_digest=self._settings.android_cert_digest,
        )

        accepted = key_verdict.ok and integrity_ok
        status = "verified" if accepted else "failed"

        if not accepted and self._settings.attestation_mode == "strict":
            await self._audit.failure(
                AuditEvent.DEVICE_ENROLL_DENIED,
                actor_type="anonymous",
                actor_id=claimed["user_id"],
                client_ip=client_ip,
                detail={
                    "reason": "attestation_rejected",
                    "key_attestation": key_verdict.as_detail(),
                    "play_integrity": integrity_detail,
                },
            )
            raise AuthenticationError("attestation_rejected")

        if not accepted:
            # log_only: the device is enrolled but flagged, and every
            # subsequent decision can see that it was never proven.
            status = "exempt"

        try:
            device_id = await self._devices.create(
                user_id=claimed["user_id"],
                label=label,
                public_key=base64.b64decode(device_public_key_b64, validate=True),
                platform="android",
                app_version=app_version,
                attestation_status=status,
                attestation_detail={
                    "key_attestation": key_verdict.as_detail(),
                    "play_integrity": integrity_detail,
                },
            )
        except Exception as exc:  # duplicate public key, mostly
            await self._audit.failure(
                AuditEvent.DEVICE_ENROLL_DENIED,
                actor_type="anonymous",
                actor_id=claimed["user_id"],
                client_ip=client_ip,
                detail={"reason": "device_create_failed", "error": type(exc).__name__},
            )
            raise Conflict("device_already_enrolled") from exc

        await self._enrollments.attach_device(claimed["id"], device_id)
        pair = await self._auth.issue_pair(
            user_id=claimed["user_id"], device_id=device_id
        )
        await self._audit.success(
            AuditEvent.DEVICE_ENROLL,
            actor_type="user",
            actor_id=claimed["user_id"],
            device_id=device_id,
            client_ip=client_ip,
            detail={
                "label": label,
                "attestation_status": status,
                "security_level": key_verdict.security_level,
                "boot_state": key_verdict.boot_state,
            },
        )
        return device_id, status, pair
