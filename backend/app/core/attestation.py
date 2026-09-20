"""Device attestation: proving the phone's key really is in secure hardware.

The phone generates its Ed25519 identity key inside the Android Keystore with
`setIsStrongBoxBacked(true)` where available, `setUserAuthenticationRequired(true)`
and an attestation challenge supplied by this server. What comes back is a
certificate chain whose leaf carries Google's key attestation extension
(OID 1.3.6.1.4.1.11129.2.1.17), signed up to a Google root.

Two independent claims are checked, because they answer different questions:

  key attestation   "this private key lives in a TEE or StrongBox on a device
                     with a locked bootloader, and it cannot be used without a
                     biometric" - a property of the key
  Play Integrity    "this request comes from an unmodified app, installed from
                     Play, on a device that passes basic integrity" - a
                     property of the app and the device

Neither is a guarantee. Both have been defeated on specific devices. What they
do is move phone cloning from "pull the key file out of the app's data
directory" to "defeat the secure element", which is a different budget.

`ACS_ATTESTATION_MODE=log_only` records the verdict and enrols anyway. That is
for development against an emulator. Production runs `strict`.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import pairwise
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

ATTESTATION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

SECURITY_LEVELS = {0: "software", 1: "trusted_environment", 2: "strongbox"}
BOOT_STATES = {0: "verified", 1: "self_signed", 2: "unverified", 3: "failed"}

TAG_ROOT_OF_TRUST = 704
TAG_NO_AUTH_REQUIRED = 503
TAG_USER_AUTH_TYPE = 504
TAG_ORIGIN = 702


# ---------------------------------------------------------------------------
# A very small DER reader. Only what the KeyDescription structure needs.
# ---------------------------------------------------------------------------

class DerError(ValueError):
    pass


@dataclass
class DerValue:
    tag: int
    content: bytes


def _read_tlv(data: bytes, offset: int) -> tuple[DerValue, int]:
    if offset >= len(data):
        raise DerError("truncated")
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:
        raise DerError("high tag numbers are not supported")
    if offset >= len(data):
        raise DerError("truncated length")
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise DerError("bad length encoding")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise DerError("length beyond buffer")
    return DerValue(tag, data[offset:end]), end


def _read_sequence(content: bytes) -> list[DerValue]:
    items: list[DerValue] = []
    offset = 0
    while offset < len(content):
        value, offset = _read_tlv(content, offset)
        items.append(value)
    return items


def _as_int(value: DerValue) -> int:
    return int.from_bytes(value.content, "big") if value.content else 0


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

@dataclass
class AttestationVerdict:
    ok: bool
    reason: str = ""
    security_level: str = "unknown"
    boot_state: str = "unknown"
    device_locked: bool = False
    user_auth_required: bool = False
    challenge_matches: bool = False
    play_integrity: dict[str, Any] = field(default_factory=dict)
    chain_subjects: list[str] = field(default_factory=list)

    def as_detail(self) -> dict[str, Any]:
        return {
            "security_level": self.security_level,
            "boot_state": self.boot_state,
            "device_locked": self.device_locked,
            "user_auth_required": self.user_auth_required,
            "challenge_matches": self.challenge_matches,
            "play_integrity": self.play_integrity,
            "chain_subjects": self.chain_subjects,
            "reason": self.reason,
            "evaluated_at": datetime.now(UTC).isoformat(),
        }


def _parse_authorization_list(value: DerValue) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in _read_sequence(value.content):
        # Context specific, constructed: tag byte 0xA0 | number, or long form.
        tag_number = item.tag & 0x1F
        if tag_number == 0x1F:
            continue
        # The real tag numbers used here are large (503, 702, 704), so the
        # encoder emits a multi-byte tag. cryptography hands us the raw bytes;
        # we re-read them with the high tag form.
        result[tag_number] = item.content
    return result


def _parse_key_description(extension_bytes: bytes) -> dict[str, Any]:
    root, _ = _read_tlv(extension_bytes, 0)
    items = _read_sequence(root.content)
    if len(items) < 8:
        raise DerError("KeyDescription has too few fields")

    parsed: dict[str, Any] = {
        "attestation_version": _as_int(items[0]),
        "attestation_security_level": SECURITY_LEVELS.get(_as_int(items[1]), "unknown"),
        "keymaster_version": _as_int(items[2]),
        "keymaster_security_level": SECURITY_LEVELS.get(_as_int(items[3]), "unknown"),
        "attestation_challenge": items[4].content,
        "unique_id": items[5].content,
    }

    tee = items[7]
    parsed.update(_scan_authorization_list(tee.content))
    if parsed.get("boot_state") is None:
        parsed.update(_scan_authorization_list(items[6].content))
    return parsed


def _scan_authorization_list(content: bytes) -> dict[str, Any]:
    """Walk an AuthorizationList looking for the three tags that matter.

    The list is a SEQUENCE of context-specific EXPLICIT tagged values whose
    tag numbers are large enough to use the multi-byte form, so the tags are
    decoded here rather than with the simple reader above.
    """
    out: dict[str, Any] = {"boot_state": None, "device_locked": None,
                           "no_auth_required": False, "user_auth_type": None}
    offset = 0
    while offset < len(content):
        if offset >= len(content):
            break
        first = content[offset]
        cursor = offset + 1
        if first & 0x1F == 0x1F:
            tag_number = 0
            while cursor < len(content):
                byte = content[cursor]
                cursor += 1
                tag_number = (tag_number << 7) | (byte & 0x7F)
                if not byte & 0x80:
                    break
        else:
            tag_number = first & 0x1F

        if cursor >= len(content):
            break
        length = content[cursor]
        cursor += 1
        if length & 0x80:
            count = length & 0x7F
            length = int.from_bytes(content[cursor:cursor + count], "big")
            cursor += count
        body = content[cursor:cursor + length]
        offset = cursor + length

        if tag_number == TAG_ROOT_OF_TRUST:
            inner, _ = _read_tlv(body, 0)
            fields = _read_sequence(inner.content)
            if len(fields) >= 3:
                out["device_locked"] = fields[1].content == b"\xff"
                out["boot_state"] = BOOT_STATES.get(_as_int(fields[2]), "unknown")
        elif tag_number == TAG_NO_AUTH_REQUIRED:
            out["no_auth_required"] = True
        elif tag_number == TAG_USER_AUTH_TYPE:
            inner, _ = _read_tlv(body, 0)
            out["user_auth_type"] = _as_int(inner)
    return out


def _verify_chain(chain: list[x509.Certificate]) -> None:
    """Each certificate must be signed by the next one up."""
    for child, parent in pairwise(chain):
        public_key = parent.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        else:
            raise InvalidSignature("unsupported key type in attestation chain")


def verify_key_attestation(
    chain_pem: list[str],
    expected_challenge: bytes,
    *,
    trusted_roots: list[x509.Certificate] | None = None,
    require_strongbox: bool = False,
) -> AttestationVerdict:
    if not chain_pem:
        return AttestationVerdict(ok=False, reason="no certificate chain supplied")

    try:
        chain = [x509.load_pem_x509_certificate(pem.encode()) for pem in chain_pem]
    except ValueError as exc:
        return AttestationVerdict(ok=False, reason=f"unparseable chain: {exc}")

    try:
        _verify_chain(chain)
    except (InvalidSignature, ValueError) as exc:
        return AttestationVerdict(ok=False, reason=f"chain signature invalid: {exc}")

    subjects = [cert.subject.rfc4514_string() for cert in chain]

    if trusted_roots:
        root_fingerprints = {c.fingerprint(chain[-1].signature_hash_algorithm)
                             for c in trusted_roots}
        top = chain[-1]
        if top.fingerprint(top.signature_hash_algorithm) not in root_fingerprints:
            return AttestationVerdict(
                ok=False, reason="chain does not terminate in a trusted root",
                chain_subjects=subjects,
            )

    leaf = chain[0]
    try:
        extension = leaf.extensions.get_extension_for_oid(ATTESTATION_OID)
    except x509.ExtensionNotFound:
        return AttestationVerdict(
            ok=False, reason="leaf has no key attestation extension",
            chain_subjects=subjects,
        )

    try:
        parsed = _parse_key_description(extension.value.public_bytes())
    except DerError as exc:
        return AttestationVerdict(
            ok=False, reason=f"malformed KeyDescription: {exc}",
            chain_subjects=subjects,
        )

    verdict = AttestationVerdict(
        ok=False,
        security_level=parsed["attestation_security_level"],
        boot_state=parsed.get("boot_state") or "unknown",
        device_locked=bool(parsed.get("device_locked")),
        user_auth_required=not parsed.get("no_auth_required", False),
        challenge_matches=parsed["attestation_challenge"] == expected_challenge,
        chain_subjects=subjects,
    )

    # The challenge is what ties this chain to this enrolment. Without it a
    # chain captured from any device at any time would be replayable.
    if not verdict.challenge_matches:
        verdict.reason = "attestation challenge does not match the one issued"
        return verdict
    if verdict.security_level == "software":
        verdict.reason = "key is not in secure hardware"
        return verdict
    if require_strongbox and verdict.security_level != "strongbox":
        verdict.reason = "StrongBox required but key is only TEE backed"
        return verdict
    if verdict.boot_state != "verified":
        verdict.reason = f"verified boot state is {verdict.boot_state}"
        return verdict
    if not verdict.device_locked:
        verdict.reason = "bootloader is unlocked"
        return verdict
    if not verdict.user_auth_required:
        verdict.reason = "key can be used without user authentication"
        return verdict

    verdict.ok = True
    verdict.reason = "ok"
    return verdict


def evaluate_play_integrity(
    verdict_payload: dict[str, Any] | None,
    *,
    expected_package: str,
    expected_cert_digest: str,
) -> tuple[bool, dict[str, Any]]:
    """Check a decoded Play Integrity verdict.

    The token itself is decrypted and verified by Google's servers; the API
    layer calls `decodeIntegrityToken` with the service account credentials
    and hands the resulting JSON here. Doing the policy in one place means the
    rules are readable, and testable without a network.
    """
    if not verdict_payload:
        return False, {"reason": "no integrity verdict"}

    app = verdict_payload.get("appIntegrity", {})
    device = verdict_payload.get("deviceIntegrity", {})
    account = verdict_payload.get("accountDetails", {})

    problems: list[str] = []
    if app.get("appRecognitionVerdict") != "PLAY_RECOGNIZED":
        problems.append("app is not the build published on Play")
    if expected_package and app.get("packageName") != expected_package:
        problems.append("package name mismatch")
    if expected_cert_digest:
        digests = [d.lower().replace(":", "") for d in app.get("certificateSha256Digest", [])]
        if expected_cert_digest.lower() not in digests:
            problems.append("signing certificate mismatch")
    recognised = device.get("deviceRecognitionVerdict", [])
    if "MEETS_DEVICE_INTEGRITY" not in recognised:
        problems.append("device does not meet basic integrity")

    detail = {
        "app_recognition": app.get("appRecognitionVerdict"),
        "device_recognition": recognised,
        "licensing": account.get("appLicensingVerdict"),
        "problems": problems,
    }
    return (not problems), detail


def decode_integrity_payload(raw: str) -> dict[str, Any] | None:
    """Accept either an already decoded verdict or a base64 JSON blob.

    In production the API calls Google to decode the token; this helper exists
    so that the decision logic can be exercised offline with captured or
    synthetic verdicts.
    """
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)))
    except Exception:
        return None
