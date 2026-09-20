from __future__ import annotations

import json
import uuid
from typing import Any

import asyncpg


class AuditRepository:
    """Append and read. There is no update method and no delete method here,
    because there is no grant that would let one succeed.

    `prev_hash` and `row_hash` are not columns this code writes: the BEFORE
    INSERT trigger in migration 005 sets them from the row the database is
    about to store. Passing values for them would be silently overwritten,
    which is the point - the application is not trusted to describe its own
    history.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def append(
        self,
        *,
        event_type: str,
        outcome: str,
        actor_type: str,
        actor_id: uuid.UUID | None = None,
        device_id: uuid.UUID | None = None,
        door_id: uuid.UUID | None = None,
        controller_id: uuid.UUID | None = None,
        client_ip: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> int:
        return await self._pool.fetchval(
            """
            INSERT INTO acs.audit_log
                (event_type, outcome, actor_type, actor_id, device_id,
                 door_id, controller_id, client_ip, detail)
            VALUES ($1, $2::acs.audit_outcome, $3::acs.actor_type, $4, $5,
                    $6, $7, $8::inet, $9::jsonb)
            RETURNING seq
            """,
            event_type, outcome, actor_type, actor_id, device_id,
            door_id, controller_id, client_ip, json.dumps(detail or {}),
        )

    async def recent(
        self, *, limit: int = 100, before_seq: int | None = None,
        event_type: str | None = None, actor_id: uuid.UUID | None = None,
    ) -> list[asyncpg.Record]:
        return await self._pool.fetch(
            """
            SELECT seq, occurred_at, event_type, outcome, actor_type, actor_id,
                   device_id, door_id, controller_id, client_ip, detail,
                   encode(row_hash, 'hex') AS row_hash
            FROM acs.audit_log
            WHERE ($2::bigint IS NULL OR seq < $2)
              AND ($3::text  IS NULL OR event_type = $3)
              AND ($4::uuid  IS NULL OR actor_id = $4)
            ORDER BY seq DESC
            LIMIT $1
            """,
            limit, before_seq, event_type, actor_id,
        )

    async def for_user(self, user_id: uuid.UUID, limit: int = 50) -> list[asyncpg.Record]:
        return await self._pool.fetch(
            """
            SELECT seq, occurred_at, event_type, outcome, door_id, detail
            FROM acs.audit_log
            WHERE actor_id = $1
              AND event_type IN ('door.unlock_granted', 'door.unlock_denied',
                                 'door.unlock_confirmed', 'door.unlock_failed')
            ORDER BY seq DESC
            LIMIT $2
            """,
            user_id, limit,
        )

    async def verify_chain(self, from_seq: int = 0) -> asyncpg.Record:
        return await self._pool.fetchrow(
            "SELECT * FROM acs.verify_audit_chain($1)", from_seq
        )

    async def head(self) -> asyncpg.Record | None:
        return await self._pool.fetchrow(
            "SELECT seq, occurred_at, encode(row_hash,'hex') AS row_hash "
            "FROM acs.audit_chain_head()"
        )
