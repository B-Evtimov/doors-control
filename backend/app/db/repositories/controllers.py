from __future__ import annotations

import uuid

import asyncpg


class ControllerRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def by_code(self, code: str) -> asyncpg.Record | None:
        return await self._pool.fetchrow(
            """
            SELECT id, code, name, public_key, beacon_key, firmware_version,
                   is_blocked, blocked_reason, last_seen_at, last_ip, created_at
            FROM acs.controllers WHERE code = $1
            """,
            code,
        )

    async def by_id(self, controller_id: uuid.UUID) -> asyncpg.Record | None:
        return await self._pool.fetchrow(
            """
            SELECT id, code, name, public_key, beacon_key, firmware_version,
                   is_blocked, last_seen_at
            FROM acs.controllers WHERE id = $1
            """,
            controller_id,
        )

    async def register(
        self, *, code: str, name: str, public_key: bytes, beacon_key: bytes
    ) -> uuid.UUID:
        return await self._pool.fetchval(
            """
            INSERT INTO acs.controllers (code, name, public_key, beacon_key)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            """,
            code, name, public_key, beacon_key,
        )

    async def touch_seen(
        self, controller_id: uuid.UUID, *, ip: str | None = None,
        firmware_version: str | None = None,
    ) -> None:
        await self._pool.execute(
            """
            UPDATE acs.controllers
            SET last_seen_at = now(),
                last_ip = coalesce($2::inet, last_ip),
                firmware_version = coalesce($3, firmware_version)
            WHERE id = $1
            """,
            controller_id, ip, firmware_version,
        )

    async def block(self, controller_id: uuid.UUID, reason: str) -> None:
        await self._pool.execute(
            """
            UPDATE acs.controllers SET is_blocked = true, blocked_reason = $2
            WHERE id = $1
            """,
            controller_id, reason,
        )

    async def list_all(self) -> list[asyncpg.Record]:
        return await self._pool.fetch(
            """
            SELECT id, code, name, firmware_version, is_blocked, last_seen_at, last_ip
            FROM acs.controllers ORDER BY code
            """
        )
