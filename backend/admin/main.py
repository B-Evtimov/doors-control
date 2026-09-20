"""Admin application.

Separate ASGI app, separate container, separate database role, bound to
127.0.0.1 by default.

Why it is not published: this app can grant a person access to a door, revoke
a device, and read the entire audit trail. The phone app cannot do any of
those things, so the two have nothing in common except a database. Publishing
them together would mean the internet-facing process holds code paths that
mint permissions, and every bug in the phone-facing half becomes a potential
path into the operator half.

Bound to loopback, the only way in is a shell on the host - which means
whoever reaches it already had to get past SSH or the VPN. In this deployment
it is reached over Tailscale: the admin app has no public hostname and no DNS
record at all, so it is not merely protected from the internet, it is not
addressable from it. `ACS_ADMIN_ALLOWED_CIDRS` is the belt to that braces.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Request, Response, status
from fastapi.responses import JSONResponse

from app.api.deps import AdminSessionDep, ServicesDep
from app.core.config import get_settings
from app.core.errors import AuditEvent
from app.db.pool import Database
from app.models.schemas import (
    AuditChainStatus,
    AuditEntry,
    ControllerCreate,
    ControllerSummary,
    DoorCreate,
    PermissionCreate,
)

LOG = logging.getLogger("acs.admin")

router = APIRouter(prefix="/admin/v1", tags=["admin"])


@router.get("/audit", response_model=list[AuditEntry])
async def read_audit(
    services: ServicesDep,
    _: AdminSessionDep,
    limit: int = 100,
    before_seq: int | None = None,
    event_type: str | None = None,
) -> list[AuditEntry]:
    rows = await services.audit._repo.recent(
        limit=min(limit, 500), before_seq=before_seq, event_type=event_type
    )
    return [
        AuditEntry(
            seq=row["seq"],
            occurred_at=row["occurred_at"],
            event_type=row["event_type"],
            outcome=row["outcome"],
            actor_type=row["actor_type"],
            actor_id=row["actor_id"],
            device_id=row["device_id"],
            door_id=row["door_id"],
            controller_id=row["controller_id"],
            client_ip=str(row["client_ip"]) if row["client_ip"] else None,
            detail=(json.loads(row["detail"])
                    if isinstance(row["detail"], str) else row["detail"]),
            row_hash=row["row_hash"],
        )
        for row in rows
    ]


@router.get("/audit/verify", response_model=AuditChainStatus)
async def verify_chain(
    services: ServicesDep, _: AdminSessionDep, from_seq: int = 0
) -> AuditChainStatus:
    status_row = await services.audit.chain_status(from_seq)
    head = await services.audit.head()
    return AuditChainStatus(
        chain_ok=status_row["chain_ok"],
        rows_checked=status_row["rows_checked"],
        first_bad_seq=status_row["first_bad_seq"],
        first_bad_reason=status_row["first_bad_reason"],
        head_seq=head["seq"] if head else None,
        head_hash=head["row_hash"] if head else None,
    )


@router.get("/controllers", response_model=list[ControllerSummary])
async def list_controllers(
    services: ServicesDep, _: AdminSessionDep
) -> list[ControllerSummary]:
    rows = await services.controllers.list_all()
    return [
        ControllerSummary(
            id=row["id"],
            code=row["code"],
            name=row["name"],
            firmware_version=row["firmware_version"],
            is_blocked=row["is_blocked"],
            last_seen_at=row["last_seen_at"],
            online=services.hub.is_online(row["code"]),
        )
        for row in rows
    ]


@router.post("/controllers", status_code=status.HTTP_201_CREATED)
async def register_controller(
    body: ControllerCreate, services: ServicesDep, session: AdminSessionDep
) -> dict[str, str]:
    import base64

    controller_id = await services.controllers.register(
        code=body.code,
        name=body.name,
        public_key=base64.b64decode(body.public_key, validate=True),
        beacon_key=base64.b64decode(body.beacon_key, validate=True),
    )
    await services.audit.success(
        AuditEvent.ADMIN_ACTION,
        actor_type="admin",
        actor_id=session.user_id,
        controller_id=controller_id,
        detail={"action": "controller.register", "code": body.code},
    )
    return {"controller_id": str(controller_id)}


@router.post("/controllers/{controller_id}/block", status_code=status.HTTP_204_NO_CONTENT)
async def block_controller(
    controller_id: str, reason: str, services: ServicesDep, session: AdminSessionDep
) -> Response:
    import uuid as _uuid

    cid = _uuid.UUID(controller_id)
    await services.controllers.block(cid, reason)
    await services.audit.success(
        AuditEvent.ADMIN_ACTION,
        actor_type="admin",
        actor_id=session.user_id,
        controller_id=cid,
        detail={"action": "controller.block", "reason": reason},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/doors", status_code=status.HTTP_201_CREATED)
async def create_door(
    body: DoorCreate, services: ServicesDep, session: AdminSessionDep
) -> dict[str, str]:
    door_id = await services.doors.create(
        code=body.code, name=body.name, location=body.location,
        controller_id=body.controller_id, relay_channel=body.relay_channel,
        unlock_seconds=body.unlock_seconds,
    )
    await services.audit.success(
        AuditEvent.ADMIN_ACTION,
        actor_type="admin",
        actor_id=session.user_id,
        door_id=door_id,
        detail={"action": "door.create", "code": body.code},
    )
    return {"door_id": str(door_id)}


@router.post("/permissions", status_code=status.HTTP_201_CREATED)
async def grant_permission(
    body: PermissionCreate, services: ServicesDep, session: AdminSessionDep
) -> dict[str, str]:
    permission_id = await services.permissions.grant(
        user_id=body.user_id,
        door_id=body.door_id,
        created_by=session.user_id,
        weekday_mask=body.weekday_mask,
        start_time=body.start_time.isoformat(),
        end_time=body.end_time.isoformat(),
        time_zone=body.time_zone,
        valid_until=body.valid_until,
    )
    await services.audit.success(
        AuditEvent.ADMIN_ACTION,
        actor_type="admin",
        actor_id=session.user_id,
        door_id=body.door_id,
        detail={
            "action": "permission.grant",
            "target_user": str(body.user_id),
            "weekday_mask": body.weekday_mask,
            "window": f"{body.start_time}-{body.end_time}",
            "time_zone": body.time_zone,
        },
    )
    return {"permission_id": str(permission_id)}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    if settings.admin_host not in ("127.0.0.1", "::1", "localhost"):
        LOG.warning(
            "admin app is bound to %s, which is not loopback. "
            "This app can grant door access and read the whole audit trail.",
            settings.admin_host,
        )
    database = Database(settings)
    await database.connect()
    from app.api.deps import Services

    app.state.services = Services.build(settings, database)
    try:
        yield
    finally:
        await database.close()


def create_admin_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title="Evtimov Doors Control System - admin",
        version="1.0.0",
        docs_url="/docs",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    application.include_router(router)

    networks = [
        ipaddress.ip_network(cidr, strict=False) for cidr in settings.admin_cidr_list
    ]

    @application.middleware("http")
    async def restrict_source(request: Request, call_next):
        peer = request.client.host if request.client else ""
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            return JSONResponse(status_code=403, content={"error": "forbidden"})
        if networks and not any(address in net for net in networks):
            return JSONResponse(status_code=403, content={"error": "forbidden"})
        return await call_next(request)

    return application


app = create_admin_app()
