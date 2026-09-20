"""The rotating BLE beacon identifier, and the check that the phone saw it.

What this defends against: an attacker who has somehow obtained a live access
token - malware on the phone, a token pulled out of a compromised backup - can
make a perfectly valid unlock request from anywhere on earth. Possession of a
credential says nothing about where the holder is standing.

The beacon fixes that. Each controller advertises a 16 byte identifier derived
from a secret it shares with the server:

    beacon_id(slot) = HMAC-SHA256(beacon_key, "acs-beacon:v1" || slot)[:16]
    slot            = floor(unix_seconds / rotation_seconds)

The phone reports the identifier it most recently heard. The server recomputes
the identifiers for the slots covering the freshness window and accepts the
request only if the reported value is one of them. The phone's own clock is
never consulted, so a phone with a wrong or attacker-controlled clock cannot
widen the window; freshness comes from which slot the value belongs to.

What it does not defend against: a relay. Two radios, one at the door and one
next to the phone, forward the advertisement in real time and the phone
genuinely does hear a current identifier. Mitigations are listed as T-11 in
docs/02-threat-model.md - the practical one is a round trip time bound on the
BLE exchange, which needs a connectable characteristic rather than a plain
advertisement, and it is on the roadmap rather than in this build.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

BEACON_ID_BYTES = 16
_DOMAIN = b"acs-beacon:v1"


def slot_for(timestamp: float, rotation_seconds: int) -> int:
    return int(timestamp // rotation_seconds)


def derive_beacon_id(beacon_key: bytes, slot: int) -> str:
    if len(beacon_key) != 32:
        raise ValueError("beacon_key must be 32 bytes")
    mac = hmac.new(
        beacon_key, _DOMAIN + slot.to_bytes(8, "big"), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(mac[:BEACON_ID_BYTES]).decode("ascii").rstrip("=")


def acceptable_slots(
    now: float, rotation_seconds: int, max_age_seconds: int
) -> list[int]:
    """Slots whose identifier may still be presented.

    The current slot plus as many previous ones as the freshness window spans,
    plus one to absorb the boundary: a phone that heard the beacon 1 second
    before a rotation is still inside a 60 second window afterwards.
    """
    current = slot_for(now, rotation_seconds)
    span = max(1, -(-max_age_seconds // rotation_seconds))  # ceiling division
    return [current - offset for offset in range(span + 1)]


def verify_proximity(
    beacon_key: bytes,
    presented_beacon_id: str,
    *,
    rotation_seconds: int,
    max_age_seconds: int,
    now: float | None = None,
) -> tuple[bool, int | None]:
    """Return (accepted, age_in_seconds_of_the_slot_that_matched)."""
    now = time.time() if now is None else now
    if not presented_beacon_id:
        return False, None

    presented = presented_beacon_id.strip().rstrip("=")
    current = slot_for(now, rotation_seconds)

    matched: int | None = None
    # Compared in constant time and without an early exit so that the loop
    # takes the same time whichever slot matches, or none does.
    for slot in acceptable_slots(now, rotation_seconds, max_age_seconds):
        candidate = derive_beacon_id(beacon_key, slot)
        if hmac.compare_digest(candidate, presented) and matched is None:
            matched = slot

    if matched is None:
        return False, None
    return True, (current - matched) * rotation_seconds
