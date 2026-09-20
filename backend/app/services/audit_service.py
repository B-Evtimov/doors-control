"""Writing to the audit log.

Every decision the system makes produces a row, including the ones that end in
a refusal, and including the ones that fail. The helper exists so that no call
site can forget the outcome field or invent its own event name.

An audit write that fails must not swallow the request it describes: the
append is awaited, and if the database refuses it the request fails too. A
door that opens without leaving a record is worse than a door that does not
open.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.core.errors import AuditEvent
from app.db.repositories.audit import AuditRepository


class AuditService:
    def __init__(self, repo: AuditRepository) -> None:
        self._repo = repo

    async def record(
        self,
        event: AuditEvent | str,
        outcome: str,
        *,
        actor_type: str = "system",
        actor_id: uuid.UUID | None = None,
        device_id: uuid.UUID | None = None,
        door_id: uuid.UUID | None = None,
        controller_id: uuid.UUID | None = None,
        client_ip: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> int:
        return await self._repo.append(
            event_type=str(event),
            outcome=outcome,
            actor_type=actor_type,
            actor_id=actor_id,
            device_id=device_id,
            door_id=door_id,
            controller_id=controller_id,
            client_ip=client_ip,
            detail=detail or {},
        )

    async def success(self, event: AuditEvent | str, **kwargs: Any) -> int:
        return await self.record(event, "success", **kwargs)

    async def failure(self, event: AuditEvent | str, **kwargs: Any) -> int:
        return await self.record(event, "failure", **kwargs)

    async def denied(self, event: AuditEvent | str, **kwargs: Any) -> int:
        return await self.record(event, "denied", **kwargs)

    async def chain_status(self, from_seq: int = 0):
        return await self._repo.verify_chain(from_seq)

    async def head(self):
        return await self._repo.head()
