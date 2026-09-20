"""Pydantic models for everything that crosses the API boundary.

Every request body and every response body has a model. Nothing is read
straight out of a dict, and nothing is serialised straight out of a database
record: a column added to a table does not become a field on a response by
accident.
"""

from __future__ import annotations

import uuid
from datetime import datetime, time
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Base64Str = Annotated[str, Field(min_length=4, max_length=8192)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------------------
# Enrolment
# ---------------------------------------------------------------------------

class EnrollChallengeRequest(StrictModel):
    enrollment_code: str = Field(min_length=8, max_length=128)


class EnrollChallengeResponse(BaseModel):
    challenge: str = Field(description="Base64. Feed this to setAttestationChallenge().")
    expires_in: int


class EnrollRequest(StrictModel):
    enrollment_code: str = Field(min_length=8, max_length=128)
    label: str = Field(min_length=1, max_length=64)
    device_public_key: Base64Str = Field(
        description="Raw Ed25519 public key, 32 bytes, base64."
    )
    attestation_chain: list[str] = Field(
        default_factory=list, max_length=8,
        description="PEM certificates, leaf first, from KeyStore.getCertificateChain().",
    )
    play_integrity_token: str = Field(default="", max_length=8192)
    challenge: Base64Str
    platform: Literal["android"] = "android"
    app_version: str | None = Field(default=None, max_length=32)

    @field_validator("device_public_key")
    @classmethod
    def _key_shape(cls, value: str) -> str:
        import base64
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32:
            raise ValueError("device_public_key must decode to 32 bytes")
        return value


class EnrollResponse(BaseModel):
    device_id: uuid.UUID
    attestation_status: str
    access_token: str
    refresh_token: str
    expires_in: int


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class LoginRequest(StrictModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=512)
    device_id: uuid.UUID


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105 - a scheme name
    expires_in: int


class RefreshRequest(StrictModel):
    refresh_token: str = Field(min_length=16, max_length=256)


class LogoutRequest(StrictModel):
    refresh_token: str | None = Field(default=None, max_length=256)
    all_devices: bool = False


# ---------------------------------------------------------------------------
# Doors and unlocking
# ---------------------------------------------------------------------------

class DoorSummary(BaseModel):
    id: uuid.UUID
    code: str
    name: str
    location: str | None
    unlock_seconds: int
    controller_online: bool
    window_start: time
    window_end: time
    weekday_mask: int
    time_zone: str


class DoorListResponse(BaseModel):
    doors: list[DoorSummary]
    server_time: datetime


class UnlockRequest(StrictModel):
    """The proximity proof is the beacon identifier the phone most recently
    heard from this door's controller. The phone does not send a timestamp:
    freshness is decided by which rotation slot the value belongs to, so a
    wrong or manipulated clock on the phone buys nothing."""

    proximity_beacon_id: str = Field(min_length=8, max_length=64)
    client_request_id: uuid.UUID | None = None


class UnlockResponse(BaseModel):
    result: Literal["opened"]
    door_id: uuid.UUID
    command_id: uuid.UUID
    opened_for_ms: int
    proximity_age_seconds: int


class UnlockDeniedResponse(BaseModel):
    error: str
    retry_after_seconds: int | None = None


# ---------------------------------------------------------------------------
# History and health
# ---------------------------------------------------------------------------

class AccessRecord(BaseModel):
    seq: int
    occurred_at: datetime
    event_type: str
    outcome: str
    door_id: uuid.UUID | None
    detail: dict[str, Any]


class AccessHistoryResponse(BaseModel):
    records: list[AccessRecord]


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    database: bool
    signer: bool
    controllers_online: int
    audit_chain_ok: bool | None = None


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

class ControllerCreate(StrictModel):
    code: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9-]+$")
    name: str = Field(min_length=1, max_length=128)
    public_key: Base64Str
    beacon_key: Base64Str


class ControllerSummary(BaseModel):
    id: uuid.UUID
    code: str
    name: str
    firmware_version: str | None
    is_blocked: bool
    last_seen_at: datetime | None
    online: bool


class DoorCreate(StrictModel):
    code: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9-]+$")
    name: str = Field(min_length=1, max_length=128)
    location: str | None = Field(default=None, max_length=128)
    controller_id: uuid.UUID | None = None
    relay_channel: int = Field(default=1, ge=1, le=4)
    unlock_seconds: int = Field(default=3, ge=1, le=10)


class PermissionCreate(StrictModel):
    user_id: uuid.UUID
    door_id: uuid.UUID
    weekday_mask: int = Field(default=127, ge=0, le=127)
    start_time: time = time(0, 0, 0)
    end_time: time = time(23, 59, 59)
    time_zone: str = Field(default="Europe/Sofia", max_length=64)
    valid_until: datetime | None = None


class AuditQuery(StrictModel):
    limit: int = Field(default=100, ge=1, le=500)
    before_seq: int | None = None
    event_type: str | None = Field(default=None, max_length=64)
    actor_id: uuid.UUID | None = None


class AuditEntry(BaseModel):
    seq: int
    occurred_at: datetime
    event_type: str
    outcome: str
    actor_type: str
    actor_id: uuid.UUID | None
    device_id: uuid.UUID | None
    door_id: uuid.UUID | None
    controller_id: uuid.UUID | None
    client_ip: str | None
    detail: dict[str, Any]
    row_hash: str


class AuditChainStatus(BaseModel):
    chain_ok: bool
    rows_checked: int
    first_bad_seq: int | None
    first_bad_reason: str | None
    head_seq: int | None
    head_hash: str | None
