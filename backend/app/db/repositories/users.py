from __future__ import annotations

import uuid

import asyncpg


class UserRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def by_username(self, username: str) -> asyncpg.Record | None:
        return await self._pool.fetchrow(
            """
            SELECT id, username, display_name, password_hash, is_admin,
                   is_active, created_at, last_login_at
            FROM acs.users
            WHERE lower(username) = lower($1)
            """,
            username,
        )

    async def by_id(self, user_id: uuid.UUID) -> asyncpg.Record | None:
        return await self._pool.fetchrow(
            """
            SELECT id, username, display_name, is_admin, is_active, created_at
            FROM acs.users WHERE id = $1
            """,
            user_id,
        )

    async def create(
        self, username: str, display_name: str, password_hash: str, *, is_admin: bool = False
    ) -> uuid.UUID:
        return await self._pool.fetchval(
            """
            INSERT INTO acs.users (username, display_name, password_hash, is_admin)
            VALUES (lower($1), $2, $3, $4)
            RETURNING id
            """,
            username, display_name, password_hash, is_admin,
        )

    async def touch_login(self, user_id: uuid.UUID) -> None:
        await self._pool.execute(
            "UPDATE acs.users SET last_login_at = now(), updated_at = now() WHERE id = $1",
            user_id,
        )

    async def set_active(self, user_id: uuid.UUID, active: bool) -> None:
        await self._pool.execute(
            "UPDATE acs.users SET is_active = $2, updated_at = now() WHERE id = $1",
            user_id, active,
        )
