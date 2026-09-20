"""Listing doors and opening them."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Request

from app.api.deps import ServicesDep, SessionDep, client_ip
from app.core.errors import ApiError, http_error
from app.models.schemas import (
    AccessHistoryResponse,
    AccessRecord,
    DoorListResponse,
    DoorSummary,
    UnlockRequest,
    UnlockResponse,
)

router = APIRouter(prefix="/api/v1", tags=["doors"])


@router.get("/doors", response_model=DoorListResponse)
async def list_doors(services: ServicesDep, session: SessionDep) -> DoorListResponse:
    rows = await services.doors.list_for_user(session.user_id)
    return DoorListResponse(
        doors=[
            DoorSummary(
                id=row["id"],
                code=row["code"],
                name=row["name"],
                location=row["location"],
                unlock_seconds=row["unlock_seconds"],
                # The database knows when the controller was last seen; the
                # hub knows whether the socket is open right now. A door is
                # only offered as openable when both agree.
                controller_online=bool(row["controller_online"]),
                window_start=row["start_time"],
                window_end=row["end_time"],
                weekday_mask=row["weekday_mask"],
                time_zone=row["time_zone"],
            )
            for row in rows
        ],
        server_time=datetime.now(UTC),
    )


@router.post("/doors/{door_id}/unlock", response_model=UnlockResponse)
async def unlock_door(
    door_id: uuid.UUID,
    body: UnlockRequest,
    request: Request,
    services: ServicesDep,
    session: SessionDep,
) -> UnlockResponse:
    try:
        outcome = await services.unlock.unlock(
            user_id=session.user_id,
            device_id=session.device_id,
            door_id=door_id,
            proximity_beacon_id=body.proximity_beacon_id,
            client_ip=client_ip(request, services),
        )
    except ApiError as exc:
        raise http_error(exc) from exc

    return UnlockResponse(
        result="opened",
        door_id=door_id,
        command_id=outcome.command_id,
        opened_for_ms=outcome.opened_for_ms,
        proximity_age_seconds=outcome.proximity_age_seconds,
    )


@router.get("/me/access-history", response_model=AccessHistoryResponse)
async def access_history(
    services: ServicesDep, session: SessionDep, limit: int = 50
) -> AccessHistoryResponse:
    """The user's own rows out of the audit log, and nothing else.

    The filter is on actor_id server side; there is no parameter that widens
    it. Seeing anyone else's history requires the admin application.
    """
    import json

    rows = await services.audit._repo.for_user(session.user_id, min(limit, 200))
    return AccessHistoryResponse(
        records=[
            AccessRecord(
                seq=row["seq"],
                occurred_at=row["occurred_at"],
                event_type=row["event_type"],
                outcome=row["outcome"],
                door_id=row["door_id"],
                detail=(json.loads(row["detail"])
                        if isinstance(row["detail"], str) else row["detail"]),
            )
            for row in rows
        ]
    )
