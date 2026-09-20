"""Login, refresh rotation and the session lookup every request goes through.

The refresh story is the interesting part. Each login starts a token *family*.
Refreshing mints a new pair whose rows point back at the token they replaced
and carry the same family id, and marks the old refresh token used. If a
refresh token that has already been used turns up again, one of two things
happened and there is no way to tell which from the server:

  * the phone retried after a lost response, or
  * somebody else has a copy of the token

So the whole family is revoked. The legitimate user is signed out and signs in
again, which is an annoyance; the thief is signed out too, which is the point.
Silently accepting the replay would leave an attacker with a session that
renews itself forever.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.core.config import Settings
from app.core.errors import AuditEvent, AuthenticationError
from app.core.security import (
    burn_password_time,
    hash_password,
    hash_token,
    new_token,
    verify_password,
)
from app.db.repositories.devices import DeviceRepository
from app.db.repositories.tokens import TokenRepository
from app.db.repositories.users import UserRepository
from app.services.audit_service import AuditService


@dataclass(frozen=True)
class Session:
    user_id: uuid.UUID
    device_id: uuid.UUID
    username: str
    display_name: str
    is_admin: bool
    token_id: uuid.UUID
    family_id: uuid.UUID


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    refresh_token: str
    expires_in: int
    family_id: uuid.UUID


class AuthService:
    def __init__(
        self,
        *,
        users: UserRepository,
        devices: DeviceRepository,
        tokens: TokenRepository,
        audit: AuditService,
        settings: Settings,
    ) -> None:
        self._users = users
        self._devices = devices
        self._tokens = tokens
        self._audit = audit
        self._settings = settings

    # ------------------------------------------------------------------ issue
    async def issue_pair(
        self,
        *,
        user_id: uuid.UUID,
        device_id: uuid.UUID,
        family_id: uuid.UUID | None = None,
        parent_id: uuid.UUID | None = None,
    ) -> IssuedTokens:
        family_id = family_id or uuid.uuid4()
        access = new_token()
        refresh = new_token()

        await self._tokens.insert(
            family_id=family_id,
            user_id=user_id,
            device_id=device_id,
            kind="access",
            token_hash=hash_token(access, self._settings),
            ttl_seconds=self._settings.access_token_ttl,
            parent_id=parent_id,
        )
        await self._tokens.insert(
            family_id=family_id,
            user_id=user_id,
            device_id=device_id,
            kind="refresh",
            token_hash=hash_token(refresh, self._settings),
            ttl_seconds=self._settings.refresh_token_ttl,
            parent_id=parent_id,
        )
        return IssuedTokens(
            access_token=access,
            refresh_token=refresh,
            expires_in=self._settings.access_token_ttl,
            family_id=family_id,
        )

    # ------------------------------------------------------------------ login
    async def login(
        self, *, username: str, password: str, device_id: uuid.UUID, client_ip: str | None
    ) -> IssuedTokens:
        user = await self._users.by_username(username)

        if user is None:
            # Spend the same CPU as a real verification would, so that a
            # missing username is not a faster answer than a wrong password.
            burn_password_time(self._settings)
            raise AuthenticationError("unknown_user")

        if not verify_password(user["password_hash"], password, self._settings):
            raise AuthenticationError("bad_password")

        if not user["is_active"]:
            burn_password_time(self._settings)
            raise AuthenticationError("user_disabled")

        device = await self._devices.by_id(device_id)
        if device is None or device["user_id"] != user["id"]:
            raise AuthenticationError("device_not_bound")
        if device["is_blocked"]:
            raise AuthenticationError("device_blocked")
        if (
            self._settings.attestation_mode == "strict"
            and device["attestation_status"] != "verified"
        ):
            raise AuthenticationError("device_not_attested")

        pair = await self.issue_pair(user_id=user["id"], device_id=device_id)
        await self._users.touch_login(user["id"])
        await self._devices.touch_seen(device_id)
        await self._audit.success(
            AuditEvent.AUTH_LOGIN,
            actor_type="user",
            actor_id=user["id"],
            device_id=device_id,
            client_ip=client_ip,
            detail={"family_id": str(pair.family_id)},
        )
        return pair

    # ---------------------------------------------------------------- refresh
    async def refresh(self, *, refresh_token: str, client_ip: str | None) -> IssuedTokens:
        record = await self._tokens.lookup(
            hash_token(refresh_token, self._settings), "refresh"
        )
        if record is None:
            raise AuthenticationError("unknown_refresh_token")

        if record["used_at"] is not None:
            # Replay. Burn the family; both the honest holder and whoever else
            # has a copy lose the session.
            revoked = await self._tokens.revoke_family(
                record["family_id"], "refresh token reuse detected"
            )
            await self._audit.failure(
                AuditEvent.AUTH_REFRESH_REUSE,
                actor_type="device",
                actor_id=record["user_id"],
                device_id=record["device_id"],
                client_ip=client_ip,
                detail={
                    "family_id": str(record["family_id"]),
                    "tokens_revoked": revoked,
                    "first_used_at": record["used_at"].isoformat(),
                },
            )
            raise AuthenticationError("refresh_reuse")

        if not TokenRepository.is_live(record):
            raise AuthenticationError("refresh_not_live")

        await self._tokens.mark_used(record["id"])
        await self._tokens.revoke(record["id"], "rotated")

        pair = await self.issue_pair(
            user_id=record["user_id"],
            device_id=record["device_id"],
            family_id=record["family_id"],
            parent_id=record["id"],
        )
        await self._audit.success(
            AuditEvent.AUTH_REFRESH,
            actor_type="user",
            actor_id=record["user_id"],
            device_id=record["device_id"],
            client_ip=client_ip,
            detail={"family_id": str(record["family_id"])},
        )
        return pair

    # --------------------------------------------------------------- sessions
    async def resolve_access_token(self, token: str) -> Session:
        record = await self._tokens.lookup(hash_token(token, self._settings), "access")
        if record is None or not TokenRepository.is_live(record):
            raise AuthenticationError("access_token_not_live")
        if (
            self._settings.attestation_mode == "strict"
            and record["attestation_status"] != "verified"
        ):
            raise AuthenticationError("device_not_attested")
        return Session(
            user_id=record["user_id"],
            device_id=record["device_id"],
            username=record["username"],
            display_name=record["display_name"],
            is_admin=record["user_is_admin"],
            token_id=record["id"],
            family_id=record["family_id"],
        )

    async def logout(
        self, *, session: Session, all_devices: bool, client_ip: str | None
    ) -> int:
        if all_devices:
            revoked = await self._tokens.revoke_device_sessions(
                session.device_id, "logout_all"
            )
        else:
            revoked = await self._tokens.revoke_family(session.family_id, "logout")
        await self._audit.success(
            AuditEvent.AUTH_LOGOUT,
            actor_type="user",
            actor_id=session.user_id,
            device_id=session.device_id,
            client_ip=client_ip,
            detail={"tokens_revoked": revoked, "all_devices": all_devices},
        )
        return revoked

    # ------------------------------------------------------------------ users
    async def create_user(
        self, *, username: str, display_name: str, password: str, is_admin: bool = False
    ) -> uuid.UUID:
        return await self._users.create(
            username, display_name, hash_password(password, self._settings),
            is_admin=is_admin,
        )
