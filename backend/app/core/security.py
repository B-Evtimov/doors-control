"""Token minting, token hashing, password hashing and response padding.

Design note, because it is the question a reviewer asks first: there is no JWT
anywhere in this system. See `docs/01-architecture.md` for the long form; the
short version is that a JWT is valid because it verifies, so revoking one
before it expires means keeping a list of revoked tokens and checking it on
every request. At that point the database round trip that JWTs were supposed
to avoid is back, and what is left is a bearer credential whose contents the
holder can read. An opaque token is a lookup key: deleting the row ends the
session on the next request, everywhere, with no propagation delay.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from app.core.config import Settings, get_settings

TOKEN_BYTES = 32


def new_token() -> str:
    """A fresh opaque token: 32 bytes of CSPRNG output, URL safe.

    It carries no structure, so there is nothing in it to parse, tamper with
    or learn from.
    """
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str, settings: Settings | None = None) -> bytes:
    """SHA-256 of pepper || token.

    A stolen database dump contains hashes. Without the pepper, which lives in
    the process environment and not in the database, the hashes are not usable
    to mint a request even by brute force: the input is 32 random bytes.

    SHA-256 rather than Argon2 on purpose. The input has 256 bits of entropy,
    so there is no dictionary to resist, and this runs on every single
    authenticated request.
    """
    settings = settings or get_settings()
    return hashlib.sha256(settings.pepper_bytes + token.encode("utf-8")).digest()


def tokens_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

def _hasher(settings: Settings) -> PasswordHasher:
    return PasswordHasher(
        time_cost=settings.argon2_time_cost,
        memory_cost=settings.argon2_memory_kib,
        parallelism=settings.argon2_parallelism,
    )


def hash_password(password: str, settings: Settings | None = None) -> str:
    settings = settings or get_settings()
    return _hasher(settings).hash(password)


def verify_password(
    stored_hash: str, password: str, settings: Settings | None = None
) -> bool:
    settings = settings or get_settings()
    try:
        return _hasher(settings).verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


# A pre-computed hash of a value nobody knows, verified against whenever the
# username does not exist. Without it, "no such user" returns in a millisecond
# and "wrong password" takes as long as Argon2 does, which is a user
# enumeration oracle that no amount of identical error text hides.
_DUMMY_PASSWORD = secrets.token_urlsafe(32)
_dummy_hash_cache: dict[tuple[int, int, int], str] = {}


def burn_password_time(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    key = (settings.argon2_time_cost, settings.argon2_memory_kib, settings.argon2_parallelism)
    stored = _dummy_hash_cache.get(key)
    if stored is None:
        stored = _hasher(settings).hash(_DUMMY_PASSWORD)
        _dummy_hash_cache[key] = stored
    verify_password(stored, "definitely not the password", settings)


# ---------------------------------------------------------------------------
# Response padding
# ---------------------------------------------------------------------------

@asynccontextmanager
async def fixed_duration(milliseconds: int) -> AsyncIterator[None]:
    """Pad the enclosed block out to a fixed wall clock duration.

    Identical error strings are not enough on their own: a database lookup
    that misses is measurably faster than one that hits and then runs Argon2.
    Every authentication path is wrapped in this so that all outcomes take the
    same observable time. If the work already took longer than the budget the
    block simply returns - the pad can only add.
    """
    started = time.perf_counter()
    try:
        yield
    finally:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        remaining = (milliseconds - elapsed_ms) / 1000.0
        if remaining > 0:
            await asyncio.sleep(remaining)


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
