"""Error types and the single response shape the API is allowed to return.

Two rules are enforced here rather than at every call site:

* Every authentication failure produces the same body and the same status.
  Whether the username exists, the password is wrong, the device is unknown or
  the token has expired is information the caller does not get.
* Every denial of an unlock produces a coarse machine readable reason from a
  fixed set. "outside the allowed hours" and "you have no grant for this door"
  both come back as `denied`; which one it was is in the audit log, which the
  person holding the phone cannot read.
"""

from __future__ import annotations

from enum import StrEnum

from fastapi import HTTPException, status


class DenyReason(StrEnum):
    """What the phone is told. Deliberately coarse."""

    DENIED = "denied"                      # no grant, wrong hours, blocked, unknown door
    NOT_PRESENT = "not_present"            # proximity proof missing or stale
    CONTROLLER_OFFLINE = "controller_offline"
    RATE_LIMITED = "rate_limited"
    FAILED = "failed"                      # controller refused or did not answer


class AuditEvent(StrEnum):
    DEVICE_ENROLL = "device.enroll"
    DEVICE_ENROLL_DENIED = "device.enroll_denied"
    AUTH_LOGIN = "auth.login"
    AUTH_LOGIN_FAILED = "auth.login_failed"
    AUTH_REFRESH = "auth.refresh"
    AUTH_REFRESH_REUSE = "auth.refresh_reuse_detected"
    AUTH_LOGOUT = "auth.logout"
    AUTH_TOKEN_REJECTED = "auth.token_rejected"  # noqa: S105 - an event name
    DOOR_UNLOCK_REQUESTED = "door.unlock_requested"
    DOOR_UNLOCK_GRANTED = "door.unlock_granted"
    DOOR_UNLOCK_DENIED = "door.unlock_denied"
    DOOR_UNLOCK_CONFIRMED = "door.unlock_confirmed"
    DOOR_UNLOCK_FAILED = "door.unlock_failed"
    RATE_LIMIT_TRIPPED = "rate.limit_tripped"
    CONTROLLER_CONNECTED = "controller.connected"
    CONTROLLER_AUTH_FAILED = "controller.auth_failed"
    CONTROLLER_DISCONNECTED = "controller.disconnected"
    ADMIN_ACTION = "admin.action"


class ApiError(Exception):
    """Base for everything the API turns into a response on purpose."""

    status_code = status.HTTP_400_BAD_REQUEST
    code = "bad_request"

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(detail or self.code)
        self.detail = detail or self.code


class AuthenticationError(ApiError):
    """Any credential problem at all. One message, one status, one timing."""

    status_code = status.HTTP_401_UNAUTHORIZED
    code = "invalid_credentials"

    def __init__(self, internal_reason: str = "unspecified") -> None:
        super().__init__(self.code)
        # Never serialised. It exists only so the audit row can be specific.
        self.internal_reason = internal_reason


class UnlockDenied(ApiError):
    status_code = status.HTTP_403_FORBIDDEN

    def __init__(self, reason: DenyReason, internal_reason: str = "") -> None:
        super().__init__(reason.value)
        self.reason = reason
        self.internal_reason = internal_reason or reason.value
        self.code = reason.value


class RateLimited(ApiError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    code = "rate_limited"

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(self.code)
        self.retry_after_seconds = retry_after_seconds


class NotFound(ApiError):
    status_code = status.HTTP_404_NOT_FOUND
    code = "not_found"


class Conflict(ApiError):
    status_code = status.HTTP_409_CONFLICT
    code = "conflict"


def http_error(err: ApiError) -> HTTPException:
    headers: dict[str, str] = {}
    if isinstance(err, RateLimited):
        headers["Retry-After"] = str(err.retry_after_seconds)
    if isinstance(err, AuthenticationError):
        headers["WWW-Authenticate"] = "Bearer"
    return HTTPException(
        status_code=err.status_code,
        detail={"error": err.code},
        headers=headers or None,
    )
