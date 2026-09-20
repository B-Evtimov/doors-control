from __future__ import annotations

import json
import uuid

import asyncpg


class DeviceRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def by_id(self, device_id: uuid.UUID) -> asyncpg.Record | None:
        return await self._pool.fetchrow(
            """
            SELECT id, user_id, label, public_key, platform, app_version,
                   attestation_status, attestation_verified_at, is_blocked,
                   blocked_reason, created_at, last_seen_at
            FROM acs.devices WHERE id = $1
            """,
            device_id,
        )

    async def for_user(self, user_id: uuid.UUID) -> list[asyncpg.Record]:
        return await self._pool.fetch(
            """
            SELECT id, label, platform, attestation_status, is_blocked,
                   created_at, last_seen_at
            FROM acs.devices WHERE user_id = $1 ORDER BY created_at
            """,
            user_id,
        )

    async def create(
        self,
        *,
        user_id: uuid.UUID,
        label: str,
        public_key: bytes,
        platform: str,
        app_version: str | None,
        attestation_status: str,
        attestation_detail: dict,
    ) -> uuid.UUID:
        return await self._pool.fetchval(
            """
            INSERT INTO acs.devices
                (user_id, label, public_key, platform, app_version,
                 attestation_status, attestation_verified_at, attestation_detail)
            VALUES ($1, $2, $3, $4, $5, $6::acs.attestation_status,
                    CASE WHEN $6 = 'verified' THEN now() ELSE NULL END,
                    $7::jsonb)
            RETURNING id
            """,
            user_id, label, public_key, platform, app_version,
            attestation_status, json.dumps(attestation_detail),
        )

    async def touch_seen(self, device_id: uuid.UUID) -> None:
        await self._pool.execute(
            "UPDATE acs.devices SET last_seen_at = now() WHERE id = $1", device_id
        )

    async def block(self, device_id: uuid.UUID, reason: str) -> None:
        await self._pool.execute(
            """
            UPDATE acs.devices SET is_blocked = true, blocked_reason = $2
            WHERE id = $1
            """,
            device_id, reason,
        )


class EnrollmentRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def create(
        self, *, user_id: uuid.UUID, code_hash: bytes, created_by: uuid.UUID | None,
        ttl_seconds: int,
    ) -> uuid.UUID:
        return await self._pool.fetchval(
            """
            INSERT INTO acs.enrollment_codes (user_id, code_hash, created_by, expires_at)
            VALUES ($1, $2, $3, now() + make_interval(secs => $4))
            RETURNING id
            """,
            user_id, code_hash, created_by, ttl_seconds,
        )

    async def claim(self, code_hash: bytes) -> asyncpg.Record | None:
        """Atomically consume an unused, unexpired code."""
        return await self._pool.fetchrow(
            """
            UPDATE acs.enrollment_codes
            SET used_at = now()
            WHERE code_hash = $1
              AND used_at IS NULL
              AND expires_at > now()
            RETURNING id, user_id
            """,
            code_hash,
        )

    async def attach_device(self, enrollment_id: uuid.UUID, device_id: uuid.UUID) -> None:
        await self._pool.execute(
            "UPDATE acs.enrollment_codes SET used_by_device = $2 WHERE id = $1",
            enrollment_id, device_id,
        )
