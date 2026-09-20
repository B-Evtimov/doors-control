"""Liveness and readiness.

`/health` is cheap and says nothing useful to a stranger. `/health/ready`
touches the database and the signer and is meant for the reverse proxy and the
container runtime, not for the internet.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.deps import ServicesDep
from app.core.signer_client import SignerRefused, SignerUnavailable
from app.models.schemas import HealthResponse

router = APIRouter(tags=["health"])

VERSION = "1.0.0"


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready", response_model=HealthResponse)
async def ready(services: ServicesDep) -> HealthResponse:
    database_ok = True
    try:
        await services.database.pool.fetchval("SELECT 1")
    except Exception:
        database_ok = False

    signer_ok = True
    try:
        await services.signer.public_key()
    except (SignerUnavailable, SignerRefused):
        signer_ok = False

    chain_ok = None
    if database_ok:
        try:
            status = await services.audit.chain_status()
            chain_ok = bool(status["chain_ok"])
        except Exception:
            chain_ok = None

    healthy = database_ok and signer_ok and chain_ok is not False
    return HealthResponse(
        status="ok" if healthy else "degraded",
        version=VERSION,
        database=database_ok,
        signer=signer_ok,
        controllers_online=services.hub.online_count,
        audit_chain_ok=chain_ok,
    )
