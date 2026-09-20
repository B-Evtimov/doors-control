from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import asyncpg


class TokenRepository:
    """Storage for opaque tokens.

    Nothing here ever sees a token in plaintext: the caller hashes it first.
    A row is a session; deleting the session is `revoked_at = now()`, which
    takes effect on the very next request because every request looks the row
    up. There is no window in which a revoked credential still works.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def insert(
        self,
        *,
        family_id: uuid.UUID,
        user_id: uuid.UUID,
        device_id: uuid.UUID,
        kind: str,
        token_hash: bytes,
        ttl_seconds: int,
        parent_id: uuid.UUID | None = None,
    ) -> uuid.UUID:
        return await self._pool.fetchval(
            """
            INSERT INTO acs.tokens
                (family_id, user_id, device_id, kind, token_hash, parent_id, expires_at)
            VALUES ($1, $2, $3, $4::acs.token_kind, $5, $6,
                    now() + make_interval(secs => $7))
            RETURNING id
            """,
            family_id, user_id, device_id, kind, token_hash, parent_id, ttl_seconds,
        )

    async def lookup(self, token_hash: bytes, kind: str) -> asyncpg.Record | None:
        return await self._pool.fetchrow(
            """
            SELECT t.id, t.family_id, t.user_id, t.device_id, t.kind,
                   t.issued_at, t.expires_at, t.used_at, t.revoked_at,
                   t.revoked_reason,
                   u.is_active   AS user_active,
                   u.is_admin    AS user_is_admin,
                   u.display_name,
                   u.username,
                   d.is_blocked  AS device_blocked,
                   d.attestation_status
            FROM acs.tokens t
            JOIN acs.users u   ON u.id = t.user_id
            JOIN acs.devices d ON d.id = t.device_id
            WHERE t.token_hash = $1 AND t.kind = $2::acs.token_kind
            """,
            token_hash, kind,
        )

    async def mark_used(self, token_id: uuid.UUID) -> None:
        await self._pool.execute(
            "UPDATE acs.tokens SET used_at = now() WHERE id = $1 AND used_at IS NULL",
            token_id,
        )

    async def revoke(self, token_id: uuid.UUID, reason: str) -> None:
        await self._pool.execute(
            """
            UPDATE acs.tokens SET revoked_at = now(), revoked_reason = $2
            WHERE id = $1 AND revoked_at IS NULL
            """,
            token_id, reason,
        )

    async def revoke_family(self, family_id: uuid.UUID, reason: str) -> int:
        """Kill every token in a family.

        This is what reuse detection triggers. If a refresh token that has
        already been rotated turns up again, either the phone replayed it or
        somebody else has a copy - and there is no way to tell which from
        here. So both sides lose the session and the real user signs in again.
        """
        return await self._pool.fetchval(
            """
            WITH revoked AS (
                UPDATE acs.tokens SET revoked_at = now(), revoked_reason = $2
                WHERE family_id = $1 AND revoked_at IS NULL
                RETURNING 1
            )
            SELECT count(*) FROM revoked
            """,
            family_id, reason,
        )

    async def revoke_device_sessions(self, device_id: uuid.UUID, reason: str) -> int:
        return await self._pool.fetchval(
            """
            WITH revoked AS (
                UPDATE acs.tokens SET revoked_at = now(), revoked_reason = $2
                WHERE device_id = $1 AND revoked_at IS NULL
                RETURNING 1
            )
            SELECT count(*) FROM revoked
            """,
            device_id, reason,
        )

    @staticmethod
    def is_live(record: asyncpg.Record, *, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return (
            record["revoked_at"] is None
            and record["expires_at"] > now
            and record["user_active"]
            and not record["device_blocked"]
        )

    @staticmethod
    def expiry(ttl_seconds: int) -> datetime:
        return datetime.now(UTC) + timedelta(seconds=ttl_seconds)
