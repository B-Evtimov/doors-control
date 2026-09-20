"""Enrolment, login, refresh, logout."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status

from app.api.deps import ServicesDep, SessionDep, client_ip
from app.core.errors import (
    ApiError,
    AuditEvent,
    AuthenticationError,
    RateLimited,
    http_error,
)
from app.core.security import fixed_duration
from app.models.schemas import (
    EnrollChallengeRequest,
    EnrollChallengeResponse,
    EnrollRequest,
    EnrollResponse,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    TokenPair,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/enroll/challenge", response_model=EnrollChallengeResponse)
async def enroll_challenge(
    body: EnrollChallengeRequest, services: ServicesDep
) -> EnrollChallengeResponse:
    """Hand out the attestation challenge.

    This deliberately answers the same way whether the enrolment code is real
    or not. A challenge is worthless without a matching unused code, which is
    checked at the next step, so there is nothing to gain from probing here.
    """
    challenge, ttl = services.enrollment.issue_challenge(body.enrollment_code)
    return EnrollChallengeResponse(challenge=challenge, expires_in=ttl)


@router.post("/enroll", response_model=EnrollResponse)
async def enroll(
    body: EnrollRequest, request: Request, services: ServicesDep
) -> EnrollResponse:
    ip = client_ip(request, services)
    async with fixed_duration(services.settings.auth_fixed_response_ms):
        try:
            device_id, status_text, pair = await services.enrollment.enroll(
                enrollment_code=body.enrollment_code,
                label=body.label,
                device_public_key_b64=body.device_public_key,
                attestation_chain=body.attestation_chain,
                play_integrity_token=body.play_integrity_token,
                presented_challenge_b64=body.challenge,
                app_version=body.app_version,
                client_ip=ip,
            )
        except ApiError as exc:
            raise http_error(exc) from exc

    return EnrollResponse(
        device_id=device_id,
        attestation_status=status_text,
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        expires_in=pair.expires_in,
    )


@router.post("/login", response_model=TokenPair)
async def login(body: LoginRequest, request: Request, services: ServicesDep) -> TokenPair:
    ip = client_ip(request, services)

    decision = await services.limiter.check_login(username=body.username, client_ip=ip)
    if not decision.allowed:
        await services.audit.denied(
            AuditEvent.RATE_LIMIT_TRIPPED,
            actor_type="anonymous",
            client_ip=ip,
            detail={
                "scope": "login",
                "subject_type": decision.subject_type,
                "failures": decision.failures,
            },
        )
        raise http_error(RateLimited(decision.retry_after_seconds))

    # Every outcome below costs the same wall clock time. The progressive
    # delay earned by earlier failures is added on top, so repeated guessing
    # gets slower without making a single attempt distinguishable.
    async with fixed_duration(services.settings.auth_fixed_response_ms):
        try:
            pair = await services.auth.login(
                username=body.username,
                password=body.password,
                device_id=body.device_id,
                client_ip=ip,
            )
        except AuthenticationError as exc:
            await services.limiter.record_login_failure(
                username=body.username, client_ip=ip, endpoint="auth.login"
            )
            await services.audit.failure(
                AuditEvent.AUTH_LOGIN_FAILED,
                actor_type="anonymous",
                device_id=body.device_id,
                client_ip=ip,
                detail={"reason": exc.internal_reason, "username": body.username},
            )
            await services.limiter.apply_delay(decision)
            raise http_error(exc) from exc

    return TokenPair(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        expires_in=pair.expires_in,
    )


@router.post("/refresh", response_model=TokenPair)
async def refresh(
    body: RefreshRequest, request: Request, services: ServicesDep
) -> TokenPair:
    ip = client_ip(request, services)
    async with fixed_duration(services.settings.auth_fixed_response_ms):
        try:
            pair = await services.auth.refresh(
                refresh_token=body.refresh_token, client_ip=ip
            )
        except AuthenticationError as exc:
            raise http_error(exc) from exc
    return TokenPair(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        expires_in=pair.expires_in,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    body: LogoutRequest,
    request: Request,
    services: ServicesDep,
    session: SessionDep,
) -> Response:
    await services.auth.logout(
        session=session,
        all_devices=body.all_devices,
        client_ip=client_ip(request, services),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
