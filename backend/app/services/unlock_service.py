"""The unlock decision, in the order the checks have to happen.

Everything here is a refusal until proven otherwise, and every branch writes
an audit row before it returns. The order is deliberate: the cheap checks that
do not touch the signer come first, so that an attacker cannot use the signer
as an oracle or as a load amplifier.

  1. door exists, is active, has a controller
  2. the user holds a live grant for this door, inside its time window
  3. the controller is not blocked
  4. the phone can prove it is near the door
  5. the user is inside the unlock rate budget
  6. the controller is actually connected
  7. the signer signs a short-lived command
  8. the controller verifies the signature and answers

The phone is told `denied` for 1, 2 and 3 without distinction. Which one it
was is in the audit log. Telling the holder of a phone that the door exists
but they are outside permitted hours is a small leak; telling them nothing
costs nothing.
"""

from __future__ import annotations

import base64
import secrets
import time
import uuid
from dataclasses import dataclass

from app.core.config import Settings
from app.core.errors import AuditEvent, DenyReason, RateLimited, UnlockDenied
from app.core.proximity import verify_proximity
from app.core.ratelimit import RateLimiter
from app.core.signer_client import SignerClient, SignerRefused, SignerUnavailable
from app.db.repositories.controllers import ControllerRepository
from app.db.repositories.doors import DoorRepository, PermissionRepository
from app.services.audit_service import AuditService
from app.ws.hub import CommandTimeout, ControllerHub, ControllerOffline


@dataclass(frozen=True)
class UnlockOutcome:
    command_id: uuid.UUID
    opened_for_ms: int
    proximity_age_seconds: int


class UnlockService:
    def __init__(
        self,
        *,
        doors: DoorRepository,
        permissions: PermissionRepository,
        controllers: ControllerRepository,
        audit: AuditService,
        signer: SignerClient,
        hub: ControllerHub,
        limiter: RateLimiter,
        settings: Settings,
    ) -> None:
        self._doors = doors
        self._permissions = permissions
        self._controllers = controllers
        self._audit = audit
        self._signer = signer
        self._hub = hub
        self._limiter = limiter
        self._settings = settings

    async def unlock(
        self,
        *,
        user_id: uuid.UUID,
        device_id: uuid.UUID,
        door_id: uuid.UUID,
        proximity_beacon_id: str,
        client_ip: str | None,
    ) -> UnlockOutcome:
        base = {
            "actor_type": "user",
            "actor_id": user_id,
            "device_id": device_id,
            "door_id": door_id,
            "client_ip": client_ip,
        }

        await self._audit.record(
            AuditEvent.DOOR_UNLOCK_REQUESTED, "success", **base
        )

        # 1 --------------------------------------------------------------- door
        door = await self._doors.by_id(door_id)
        if door is None or not door["is_active"] or door["controller_id"] is None:
            await self._deny(base, "door_unavailable", DenyReason.DENIED)

        # 2 -------------------------------------------------------- permission
        permission = await self._permissions.effective(user_id, door_id)
        if permission is None:
            await self._deny(base, "no_permission", DenyReason.DENIED)
        if not permission["within_window"]:
            await self._deny(
                base,
                "outside_time_window",
                DenyReason.DENIED,
                extra={
                    "local_time": str(permission["local_time"]),
                    "local_dow": permission["local_dow"],
                    "window": f'{permission["start_time"]}-{permission["end_time"]}',
                    "time_zone": permission["time_zone"],
                },
            )

        # 3 -------------------------------------------------------- controller
        if door["controller_blocked"]:
            await self._deny(base, "controller_blocked", DenyReason.DENIED)

        # 4 --------------------------------------------------------- proximity
        accepted, age = verify_proximity(
            bytes(door["beacon_key"]),
            proximity_beacon_id,
            rotation_seconds=self._settings.beacon_rotation_seconds,
            max_age_seconds=self._settings.proximity_max_age_seconds,
        )
        if not accepted:
            await self._deny(
                base, "proximity_not_proven", DenyReason.NOT_PRESENT,
                extra={"presented_length": len(proximity_beacon_id)},
            )

        # 5 ------------------------------------------------------- rate budget
        decision = await self._limiter.check_unlock(
            user_id=str(user_id), device_id=str(device_id)
        )
        if not decision.allowed:
            await self._audit.denied(
                AuditEvent.RATE_LIMIT_TRIPPED,
                **base,
                detail={"attempts_in_window": decision.failures, "scope": "unlock"},
            )
            raise RateLimited(decision.retry_after_seconds)

        # 6 ---------------------------------------------------- controller live
        controller_code = door["controller_code"]
        if not self._hub.is_online(controller_code):
            await self._deny(
                base, "controller_offline", DenyReason.CONTROLLER_OFFLINE,
                extra={"controller_code": controller_code},
            )

        # 7 ------------------------------------------------------------ signer
        command_id = uuid.uuid4()
        issued_at = int(time.time())
        payload = {
            "command_id": str(command_id),
            "cmd": "unlock",
            "controller_code": controller_code,
            "door_code": door["code"],
            "relay_channel": int(door["relay_channel"]),
            "duration_ms": int(door["unlock_seconds"]) * 1000,
            "issued_at": issued_at,
            "expires_at": issued_at + self._settings.command_ttl_seconds,
            "nonce": base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("="),
        }

        try:
            signature, key_id = await self._signer.sign_command(payload)
        except (SignerUnavailable, SignerRefused) as exc:
            await self._deny(
                base, f"signer_unavailable: {exc}", DenyReason.FAILED,
                controller_id=door["controller_id"],
            )
            return  # unreachable; _deny always raises

        await self._audit.success(
            AuditEvent.DOOR_UNLOCK_GRANTED,
            **base,
            controller_id=door["controller_id"],
            detail={
                "command_id": str(command_id),
                "signer_key_id": key_id,
                "proximity_age_seconds": age,
                "duration_ms": payload["duration_ms"],
            },
        )

        # 8 -------------------------------------------------------- controller
        envelope = {
            "type": "command",
            "payload": payload,
            "signature": base64.b64encode(signature).decode("ascii"),
            "key_id": key_id,
            "alg": "ed25519",
        }
        try:
            ack = await self._hub.send_command(
                controller_code, envelope,
                timeout=self._settings.command_ttl_seconds,
            )
        except ControllerOffline:
            await self._fail(base, door, command_id, "controller_disconnected")
        except CommandTimeout:
            await self._fail(base, door, command_id, "no_acknowledgement")

        if ack.get("result") != "opened":
            await self._fail(
                base, door, command_id,
                f'controller_refused:{ack.get("detail", "unspecified")}',
            )

        await self._audit.success(
            AuditEvent.DOOR_UNLOCK_CONFIRMED,
            **base,
            controller_id=door["controller_id"],
            detail={
                "command_id": str(command_id),
                "controller_uptime_ms": ack.get("uptime_ms"),
                "relay_ms": ack.get("relay_ms"),
            },
        )
        return UnlockOutcome(
            command_id=command_id,
            opened_for_ms=payload["duration_ms"],
            proximity_age_seconds=age or 0,
        )

    # ------------------------------------------------------------------ helpers
    async def _deny(
        self,
        base: dict,
        internal_reason: str,
        reason: DenyReason,
        *,
        extra: dict | None = None,
        controller_id: uuid.UUID | None = None,
    ) -> None:
        await self._audit.denied(
            AuditEvent.DOOR_UNLOCK_DENIED,
            **base,
            controller_id=controller_id,
            detail={"reason": internal_reason, **(extra or {})},
        )
        raise UnlockDenied(reason, internal_reason)

    async def _fail(
        self, base: dict, door, command_id: uuid.UUID, internal_reason: str
    ) -> None:
        await self._audit.failure(
            AuditEvent.DOOR_UNLOCK_FAILED,
            **base,
            controller_id=door["controller_id"],
            detail={"reason": internal_reason, "command_id": str(command_id)},
        )
        raise UnlockDenied(DenyReason.FAILED, internal_reason)
