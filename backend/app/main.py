"""Public API.

This is the only process exposed to the internet, and it holds the least: no
signing key, no DDL rights, and a database role that cannot delete a single
row anywhere.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api import auth as auth_router
from app.api import doors as doors_router
from app.api import health as health_router
from app.api.deps import Services
from app.core.config import get_settings
from app.core.errors import ApiError, RateLimited
from app.db.pool import Database
from app.ws import controller_ws

LOG = logging.getLogger("acs.api")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    database = Database(settings)
    await database.connect()
    app.state.services = Services.build(settings, database)
    LOG.info("api started, env=%s", settings.env)
    try:
        yield
    finally:
        await database.close()


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title="Evtimov Doors Control System",
        version=health_router.VERSION,
        # The schema is a map of the attack surface. It is served only when
        # the deployment says it is not production.
        docs_url="/docs" if settings.env != "production" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.env != "production" else None,
        lifespan=lifespan,
    )

    application.include_router(auth_router.router)
    application.include_router(doors_router.router)
    application.include_router(health_router.router)
    application.include_router(controller_ws.router)

    @application.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        headers = {}
        if isinstance(exc, RateLimited):
            headers["Retry-After"] = str(exc.retry_after_seconds)
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.code},
            headers=headers or None,
        )

    @application.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        # The API serves JSON to an app, never HTML to a browser, so the
        # policy can be as narrow as it gets.
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains"
        )
        return response

    return application


app = create_app()
