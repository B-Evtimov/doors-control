from __future__ import annotations

import asyncpg


class RateLimitRepository:
    """The durable half of rate limiting.

    In-memory counters are fast but reset when the container restarts, which
    is exactly what an attacker would arrange if they could. Counting in the
    database means a restart does not hand anybody a fresh budget, and means
    the limit holds across replicas.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def record_failure(
        self, *, subject_type: str, subject: str, endpoint: str, client_ip: str | None
    ) -> None:
        await self._pool.execute(
            """
            INSERT INTO acs.failed_attempts
                (subject_type, subject, endpoint, client_ip)
            VALUES ($1::acs.rate_subject, $2, $3, $4::inet)
            """,
            subject_type, subject, endpoint, client_ip,
        )

    async def failure_count(
        self, *, subject_type: str, subject: str, window_seconds: int,
        endpoint: str | None = None,
    ) -> int:
        return await self._pool.fetchval(
            """
            SELECT count(*)
            FROM acs.failed_attempts
            WHERE subject_type = $1::acs.rate_subject
              AND subject = $2
              AND occurred_at > now() - make_interval(secs => $3)
              AND ($4::text IS NULL OR endpoint = $4)
            """,
            subject_type, subject, window_seconds, endpoint,
        )

    async def unlock_count(self, *, user_id: str, seconds: int) -> int:
        """Successful and denied unlock attempts in the recent past.

        Counted from the audit log rather than a counter table, because the
        audit log is the one record that cannot be quietly trimmed to make
        room for more attempts.
        """
        return await self._pool.fetchval(
            """
            SELECT count(*)
            FROM acs.audit_log
            WHERE actor_id = $1::uuid
              AND event_type LIKE 'door.unlock%'
              AND occurred_at > now() - make_interval(secs => $2)
            """,
            user_id, seconds,
        )
