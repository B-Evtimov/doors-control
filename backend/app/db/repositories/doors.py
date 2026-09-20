from __future__ import annotations

import uuid

import asyncpg


class DoorRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def by_id(self, door_id: uuid.UUID) -> asyncpg.Record | None:
        return await self._pool.fetchrow(
            """
            SELECT d.id, d.code, d.name, d.location, d.relay_channel,
                   d.unlock_seconds, d.is_active, d.controller_id,
                   c.code AS controller_code, c.beacon_key,
                   c.is_blocked AS controller_blocked, c.last_seen_at AS controller_seen
            FROM acs.doors d
            LEFT JOIN acs.controllers c ON c.id = d.controller_id
            WHERE d.id = $1
            """,
            door_id,
        )

    async def list_for_user(self, user_id: uuid.UUID) -> list[asyncpg.Record]:
        """Doors the user currently holds a live grant for.

        The time window is evaluated here, in the database, in the permission's
        own time zone. The phone is told which doors it may try; the unlock
        endpoint checks the same condition again rather than trusting that the
        phone only asks for what it was shown.
        """
        return await self._pool.fetch(
            """
            SELECT d.id, d.code, d.name, d.location, d.unlock_seconds,
                   p.valid_until, p.start_time, p.end_time, p.weekday_mask,
                   p.time_zone,
                   (c.id IS NOT NULL
                    AND NOT c.is_blocked
                    AND c.last_seen_at > now() - interval '2 minutes') AS controller_online
            FROM acs.permissions p
            JOIN acs.doors d       ON d.id = p.door_id AND d.is_active
            LEFT JOIN acs.controllers c ON c.id = d.controller_id
            WHERE p.user_id = $1
              AND p.is_active
              AND p.valid_from <= now()
              AND (p.valid_until IS NULL OR p.valid_until > now())
            ORDER BY d.name
            """,
            user_id,
        )

    async def create(
        self, *, code: str, name: str, location: str | None,
        controller_id: uuid.UUID | None, relay_channel: int, unlock_seconds: int,
    ) -> uuid.UUID:
        return await self._pool.fetchval(
            """
            INSERT INTO acs.doors (code, name, location, controller_id,
                                   relay_channel, unlock_seconds)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            """,
            code, name, location, controller_id, relay_channel, unlock_seconds,
        )


class PermissionRepository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def effective(
        self, user_id: uuid.UUID, door_id: uuid.UUID
    ) -> asyncpg.Record | None:
        """The live grant for this pair, with the time window already evaluated.

        `within_window` is computed by PostgreSQL against the permission's own
        time zone, so the answer does not depend on the container's TZ and
        does not drift at a daylight saving boundary.

        Weekday bit 0 is Monday, matching ISO-8601, which is what
        `EXTRACT(isodow)` returns (1..7).
        """
        return await self._pool.fetchrow(
            """
            SELECT p.id,
                   p.valid_from,
                   p.valid_until,
                   p.weekday_mask,
                   p.start_time,
                   p.end_time,
                   p.time_zone,
                   (now() AT TIME ZONE p.time_zone)::time AS local_time,
                   EXTRACT(isodow FROM (now() AT TIME ZONE p.time_zone))::int
                       AS local_dow,
                   (
                       ((p.weekday_mask >> (
                           EXTRACT(isodow FROM (now() AT TIME ZONE p.time_zone))::int - 1
                       )) & 1) = 1
                       AND (now() AT TIME ZONE p.time_zone)::time
                           BETWEEN p.start_time AND p.end_time
                   ) AS within_window
            FROM acs.permissions p
            WHERE p.user_id = $1
              AND p.door_id = $2
              AND p.is_active
              AND p.valid_from <= now()
              AND (p.valid_until IS NULL OR p.valid_until > now())
            """,
            user_id, door_id,
        )

    async def grant(
        self,
        *,
        user_id: uuid.UUID,
        door_id: uuid.UUID,
        created_by: uuid.UUID | None,
        weekday_mask: int = 127,
        start_time: str = "00:00:00",
        end_time: str = "23:59:59",
        time_zone: str = "Europe/Sofia",
        valid_until=None,
    ) -> uuid.UUID:
        return await self._pool.fetchval(
            """
            INSERT INTO acs.permissions
                (user_id, door_id, created_by, weekday_mask,
                 start_time, end_time, time_zone, valid_until)
            VALUES ($1, $2, $3, $4, $5::text::time, $6::text::time, $7, $8)
            ON CONFLICT (user_id, door_id) WHERE is_active
            DO UPDATE SET weekday_mask = EXCLUDED.weekday_mask,
                          start_time   = EXCLUDED.start_time,
                          end_time     = EXCLUDED.end_time,
                          time_zone    = EXCLUDED.time_zone,
                          valid_until  = EXCLUDED.valid_until
            RETURNING id
            """,
            user_id, door_id, created_by, weekday_mask,
            start_time, end_time, time_zone, valid_until,
        )

    async def revoke(self, permission_id: uuid.UUID) -> None:
        await self._pool.execute(
            "UPDATE acs.permissions SET is_active = false WHERE id = $1",
            permission_id,
        )
