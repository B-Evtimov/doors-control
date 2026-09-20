"""Wiring. One container, built at startup, handed to routers by FastAPI."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, Request

from app.core.config import Settings, get_settings
from app.core.errors import AuthenticationError, http_error
from app.core.ratelimit import RateLimiter
from app.core.signer_client import SignerClient
from app.db.pool import Database
from app.db.repositories.audit import AuditRepository
from app.db.repositories.controllers import ControllerRepository
from app.db.repositories.devices import DeviceRepository, EnrollmentRepository
from app.db.repositories.doors import DoorRepository, PermissionRepository
from app.db.repositories.rate_limit import RateLimitRepository
from app.db.repositories.tokens import TokenRepository
from app.db.repositories.users import UserRepository
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService, Session
from app.services.enrollment_service import ChallengeStore, EnrollmentService
from app.services.unlock_service import UnlockService
from app.ws.hub import ControllerHub
from app.ws.hub import hub as default_hub


@dataclass
class Services:
    settings: Settings
    database: Database
    users: UserRepository
    devices: DeviceRepository
    enrollments: EnrollmentRepository
    doors: DoorRepository
    permissions: PermissionRepository
    controllers: ControllerRepository
    tokens: TokenRepository
    audit: AuditService
    auth: AuthService
    unlock: UnlockService
    enrollment: EnrollmentService
    limiter: RateLimiter
    signer: SignerClient
    hub: ControllerHub

    @classmethod
    def build(
        cls,
        settings: Settings,
        database: Database,
        *,
        hub: ControllerHub | None = None,
        signer: SignerClient | None = None,
    ) -> Services:
        pool = database.pool
        audit_repo = AuditRepository(database.audit_pool)
        audit = AuditService(audit_repo)
        users = UserRepository(pool)
        devices = DeviceRepository(pool)
        enrollments = EnrollmentRepository(pool)
        doors = DoorRepository(pool)
        permissions = PermissionRepository(pool)
        controllers = ControllerRepository(pool)
        tokens = TokenRepository(pool)
        limiter = RateLimiter(RateLimitRepository(pool), settings)
        signer = signer or SignerClient.from_settings(settings)
        hub = hub or default_hub

        auth = AuthService(
            users=users, devices=devices, tokens=tokens, audit=audit, settings=settings
        )
        unlock = UnlockService(
            doors=doors, permissions=permissions, controllers=controllers,
            audit=audit, signer=signer, hub=hub, limiter=limiter, settings=settings,
        )
        enrollment = EnrollmentService(
            enrollments=enrollments, devices=devices, auth=auth, audit=audit,
            challenges=ChallengeStore(), settings=settings,
        )
        return cls(
            settings=settings, database=database, users=users, devices=devices,
            enrollments=enrollments, doors=doors, permissions=permissions,
            controllers=controllers, tokens=tokens, audit=audit, auth=auth,
            unlock=unlock, enrollment=enrollment, limiter=limiter,
            signer=signer, hub=hub,
        )


def get_services(request: Request) -> Services:
    return request.app.state.services


ServicesDep = Annotated[Services, Depends(get_services)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


def client_ip(request: Request, services: Services) -> str | None:
    """The address used for rate limiting.

    X-Forwarded-For is honoured only when the immediate peer is one of the
    configured trusted proxies. Otherwise the header is a value the client
    chose, and trusting it would let anyone reset their own rate limit by
    changing one string.
    """
    peer = request.client.host if request.client else None
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded or not peer:
        return peer

    trusted = services.settings.trusted_proxy_list
    try:
        peer_addr = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not any(peer_addr in ipaddress.ip_network(net, strict=False) for net in trusted):
        return peer

    candidate = forwarded.split(",")[0].strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return peer
    return candidate


async def current_session(
    services: ServicesDep,
    authorization: Annotated[str | None, Header()] = None,
) -> Session:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise http_error(AuthenticationError("missing_bearer"))
    token = authorization.split(" ", 1)[1].strip()
    try:
        return await services.auth.resolve_access_token(token)
    except AuthenticationError as exc:
        raise http_error(exc) from exc


SessionDep = Annotated[Session, Depends(current_session)]


async def admin_session(session: SessionDep) -> Session:
    if not session.is_admin:
        # Same shape as any other authentication failure: a non-admin learns
        # nothing about whether the endpoint exists.
        raise http_error(AuthenticationError("not_admin"))
    return session


AdminSessionDep = Annotated[Session, Depends(admin_session)]
