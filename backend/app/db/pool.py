"""Connection pools.

Two pools, two roles. The request path uses `acs_app`. Audit rows are written
through `acs_audit` when a separate DSN is configured, so that the connection
that appends to the log is not the same connection that can read password
hashes. Both are refused UPDATE and DELETE on the audit table by the grants in
migration 006.
"""

from __future__ import annotations

import asyncpg

from app.core.config import Settings


class Database:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._app: asyncpg.Pool | None = None
        self._audit: asyncpg.Pool | None = None

    async def connect(self) -> None:
        server_settings = {
            "application_name": "acs-api",
            "statement_timeout": f"{self._settings.db_statement_timeout * 1000}",
        }
        self._app = await asyncpg.create_pool(
            self._settings.db_dsn,
            min_size=self._settings.db_pool_min,
            max_size=self._settings.db_pool_max,
            server_settings=server_settings,
        )
        audit_dsn = self._settings.audit_dsn
        if audit_dsn == self._settings.db_dsn:
            self._audit = self._app
        else:
            self._audit = await asyncpg.create_pool(
                audit_dsn,
                min_size=1,
                max_size=max(2, self._settings.db_pool_max // 2),
                server_settings={**server_settings, "application_name": "acs-audit"},
            )

    async def close(self) -> None:
        if self._audit is not None and self._audit is not self._app:
            await self._audit.close()
        if self._app is not None:
            await self._app.close()
        self._app = self._audit = None

    @property
    def pool(self) -> asyncpg.Pool:
        if self._app is None:
            raise RuntimeError("database pool is not connected")
        return self._app

    @property
    def audit_pool(self) -> asyncpg.Pool:
        if self._audit is None:
            raise RuntimeError("audit pool is not connected")
        return self._audit
