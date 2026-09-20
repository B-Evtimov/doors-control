"""Wire format shared by the signer and its only client.

Deliberately boring: one JSON object per line over a Unix domain socket. No
HTTP, no framework, no deserialisation of anything the signer did not ask for.
The signer's attack surface is this file.
"""

from __future__ import annotations

import json
from typing import Any

ALG = "ed25519"
COMMAND_DOMAIN = b"acs-command:v1\x00"

REQUIRED_COMMAND_FIELDS = (
    "command_id",
    "cmd",
    "controller_code",
    "door_code",
    "relay_channel",
    "duration_ms",
    "issued_at",
    "expires_at",
    "nonce",
)

ALLOWED_COMMANDS = ("unlock",)

# A signed command must never be valid for long. The signer enforces this
# itself rather than trusting the caller, because the caller is the process
# most likely to be compromised.
MAX_COMMAND_TTL_SECONDS = 30
MAX_DURATION_MS = 10_000


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """The exact bytes that get signed and verified.

    Sorted keys, no insignificant whitespace, UTF-8. The firmware rebuilds
    this same string from the fields it received; if it cannot, it does not
    open the door.
    """
    body = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return COMMAND_DOMAIN + body


class InvalidCommand(ValueError):
    """The signer refuses to sign this."""


def validate_command(payload: dict[str, Any]) -> None:
    missing = [f for f in REQUIRED_COMMAND_FIELDS if f not in payload]
    if missing:
        raise InvalidCommand(f"missing fields: {','.join(missing)}")

    if payload["cmd"] not in ALLOWED_COMMANDS:
        raise InvalidCommand("unknown command")

    if not isinstance(payload["duration_ms"], int) or not (
        0 < payload["duration_ms"] <= MAX_DURATION_MS
    ):
        raise InvalidCommand("duration_ms out of range")

    issued_at, expires_at = payload["issued_at"], payload["expires_at"]
    if not isinstance(issued_at, int) or not isinstance(expires_at, int):
        raise InvalidCommand("timestamps must be integers")
    ttl = expires_at - issued_at
    if not (0 < ttl <= MAX_COMMAND_TTL_SECONDS):
        raise InvalidCommand("command ttl out of range")

    if not isinstance(payload["nonce"], str) or len(payload["nonce"]) < 16:
        raise InvalidCommand("nonce too short")


def encode_request(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8") + b"\n"


def decode_line(line: bytes) -> dict[str, Any]:
    obj = json.loads(line.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("expected a JSON object")
    return obj
