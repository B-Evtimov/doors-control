"""Test fixtures.

Everything here runs against a real PostgreSQL 16 and a real signer process.
Nothing about the database layer is mocked, because the database layer is
where half the security controls live: a mock cannot refuse a DELETE that the
grants refuse.

Point the suite at a server with:

    ACS_TEST_SUPERUSER_DSN=postgresql://postgres@127.0.0.1:5432/postgres

In CI that is the `postgres:16` service container; locally it is whatever you
have. The suite creates and drops its own database.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings, reset_settings_cache  # noqa: E402
from app.core.proximity import derive_beacon_id  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.pool import Database  # noqa: E402
from app.ws.hub import ControllerHub, ControllerSession  # noqa: E402
from signer.protocol import canonical_bytes  # noqa: E402

TEST_DB = os.environ.get("ACS_TEST_DB", "acs_suite")
SUPERUSER_DSN = os.environ.get(
    "ACS_TEST_SUPERUSER_DSN", "postgresql://postgres@127.0.0.1:5432/postgres"
)

APP_PASSWORD = "app-test-password"
AUDIT_PASSWORD = "audit-test-password"
MIGRATE_PASSWORD = "migrate-test-password"


def _dsn_for(role: str, password: str, database: str) -> str:
    base = SUPERUSER_DSN.rsplit("/", 1)[0]
    scheme, _, rest = base.partition("://")
    _, _, hostpart = rest.partition("@")
    return f"{scheme}://{role}:{password}@{hostpart}/{database}"


SUPER_TEST_DSN = SUPERUSER_DSN.rsplit("/", 1)[0] + f"/{TEST_DB}"
APP_DSN = _dsn_for("acs_app", APP_PASSWORD, TEST_DB)
AUDIT_DSN = _dsn_for("acs_audit", AUDIT_PASSWORD, TEST_DB)
MIGRATE_DSN = _dsn_for("acs_migrate", MIGRATE_PASSWORD, TEST_DB)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def database_url() -> str:
    subprocess.run(
        ["psql", SUPERUSER_DSN, "-v", "ON_ERROR_STOP=1", "-q", "-c",
         f'DROP DATABASE IF EXISTS "{TEST_DB}" WITH (FORCE)'],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["psql", SUPERUSER_DSN, "-v", "ON_ERROR_STOP=1", "-q", "-c",
         f'CREATE DATABASE "{TEST_DB}"'],
        check=True, capture_output=True,
    )

    env = {
        **os.environ,
        "ACS_DB_NAME": TEST_DB,
        "ACS_BOOTSTRAP_DSN": SUPER_TEST_DSN,
        "ACS_MIGRATE_DB_DSN": MIGRATE_DSN,
        "ACS_DB_MIGRATE_PASSWORD": MIGRATE_PASSWORD,
        "ACS_DB_APP_PASSWORD": APP_PASSWORD,
        "ACS_DB_AUDIT_PASSWORD": AUDIT_PASSWORD,
        "ACS_SEED_DEV": "0",
    }
    result = subprocess.run(
        ["bash", str(BACKEND_ROOT / "db" / "apply.sh")],
        env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"migrations failed:\n{result.stdout}\n{result.stderr}")
    return APP_DSN


# ---------------------------------------------------------------------------
# Signer, as a real separate process on a real Unix socket
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def signer_process():
    key = Ed25519PrivateKey.generate()
    private_b64 = base64.b64encode(key.private_bytes_raw()).decode()
    public_raw = key.public_key().public_bytes_raw()

    tmp = tempfile.mkdtemp(prefix="acs-signer-")
    socket_path = str(Path(tmp) / "signer.sock")

    process = subprocess.Popen(
        [sys.executable, "-m", "signer.server"],
        cwd=str(BACKEND_ROOT),
        env={
            **os.environ,
            "PYTHONPATH": str(BACKEND_ROOT),
            "ACS_SIGNER_SOCKET": socket_path,
            "ACS_SIGNER_PRIVATE_KEY": private_b64,
            "ACS_SIGNER_KEY_ID": "test-signer",
        },
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )

    deadline = time.time() + 10
    while not Path(socket_path).exists():
        if time.time() > deadline or process.poll() is not None:
            out, err = process.communicate(timeout=5)
            raise RuntimeError(f"signer did not start: {out!r} {err!r}")
        time.sleep(0.05)

    yield {"socket": socket_path, "public_key": public_raw, "key_id": "test-signer"}

    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:  # pragma: no cover
        process.kill()


@pytest.fixture(scope="session")
def configured_environment(database_url: str, signer_process: dict):
    os.environ.update(
        {
            "ACS_ENV": "test",
            "ACS_DB_DSN": database_url,
            "ACS_AUDIT_DB_DSN": AUDIT_DSN,
            "ACS_TOKEN_PEPPER": base64.b64encode(secrets.token_bytes(32)).decode(),
            "ACS_SIGNER_SOCKET": signer_process["socket"],
            "ACS_SIGNER_KEY_ID": signer_process["key_id"],
            # Argon2 at production cost makes the suite take minutes for no
            # extra assurance. The timing test measures the *difference*
            # between outcomes, which this does not change.
            "ACS_ARGON2_TIME_COST": "1",
            "ACS_ARGON2_MEMORY_KIB": "8192",
            "ACS_ARGON2_PARALLELISM": "1",
            "ACS_AUTH_FIXED_RESPONSE_MS": "120",
            "ACS_ATTESTATION_MODE": "log_only",
            "ACS_RATE_MAX_LOGIN_FAILURES": "5",
            "ACS_RATE_MAX_UNLOCKS_PER_MINUTE": "6",
            "ACS_RATE_BASE_DELAY_MS": "1",
            "ACS_RATE_MAX_DELAY_MS": "5",
            "ACS_COMMAND_TTL_SECONDS": "5",
        }
    )
    reset_settings_cache()
    return get_settings()


# ---------------------------------------------------------------------------
# Per-test wiring
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def services(configured_environment):
    from app.api.deps import Services

    settings = configured_environment
    database = Database(settings)
    await database.connect()

    # Operational tables are cleared between tests with the migration role,
    # which is the only one that could - the application role holds no DELETE
    # anywhere. acs.audit_log is never cleared, because nothing can clear it.
    admin_conn = await asyncpg.connect(MIGRATE_DSN)
    try:
        await admin_conn.execute(
            "DELETE FROM acs.tokens;"
            "DELETE FROM acs.permissions;"
            "DELETE FROM acs.enrollment_codes;"
            "DELETE FROM acs.devices;"
            "DELETE FROM acs.doors;"
            "DELETE FROM acs.controllers;"
            "DELETE FROM acs.users;"
            "DELETE FROM acs.failed_attempts;"
        )
    finally:
        await admin_conn.close()

    container = Services.build(settings, database, hub=ControllerHub())
    try:
        yield container
    finally:
        await database.close()


@pytest_asyncio.fixture
async def api_client(services):
    """The real ASGI app, with the same Services container the tests poke at."""
    import httpx

    from app.main import create_app

    application = create_app()
    application.router.lifespan_context = _no_lifespan
    application.state.services = services

    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        yield client


from contextlib import asynccontextmanager  # noqa: E402


@asynccontextmanager
async def _no_lifespan(app):
    yield


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------

class World:
    """A user with a phone, a door, a controller and a grant.

    Built through the real repositories so that the rows are exactly what the
    application would have written.
    """

    def __init__(self, services) -> None:
        self.services = services
        self.password = "correct horse battery staple"

    async def build(
        self,
        *,
        weekday_mask: int = 127,
        start_time: str = "00:00:00",
        end_time: str = "23:59:59",
        grant: bool = True,
    ) -> World:
        settings = self.services.settings
        self.user_id = await self.services.users.create(
            f"user{secrets.token_hex(4)}",
            "Test User",
            hash_password(self.password, settings),
        )
        self.username = (await self.services.users.by_id(self.user_id))["username"]

        self.device_id = await self.services.devices.create(
            user_id=self.user_id,
            label="Pixel",
            public_key=Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
            platform="android",
            app_version="1.0.0",
            attestation_status="verified",
            attestation_detail={},
        )

        self.controller_key = Ed25519PrivateKey.generate()
        self.beacon_key = secrets.token_bytes(32)
        self.controller_code = f"ctrl-{secrets.token_hex(3)}"
        self.controller_id = await self.services.controllers.register(
            code=self.controller_code,
            name="Test controller",
            public_key=self.controller_key.public_key().public_bytes_raw(),
            beacon_key=self.beacon_key,
        )

        self.door_id = await self.services.doors.create(
            code=f"door-{secrets.token_hex(3)}",
            name="Front door",
            location="Test",
            controller_id=self.controller_id,
            relay_channel=1,
            unlock_seconds=3,
        )

        if grant:
            await self.services.permissions.grant(
                user_id=self.user_id,
                door_id=self.door_id,
                created_by=None,
                weekday_mask=weekday_mask,
                start_time=start_time,
                end_time=end_time,
                time_zone="UTC",
            )

        self.tokens = await self.services.auth.issue_pair(
            user_id=self.user_id, device_id=self.device_id
        )
        return self

    def fresh_beacon(self, age_seconds: int = 0) -> str:
        rotation = self.services.settings.beacon_rotation_seconds
        slot = int((time.time() - age_seconds) // rotation)
        return derive_beacon_id(self.beacon_key, slot)

    @property
    def auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.tokens.access_token}"}


class FakeController:
    """A controller that behaves. Verifies the signature, answers "opened".

    The verification is the real one - the same Ed25519 check the firmware
    does - so a test that tampers with a command fails here for the same
    reason it would fail on the board.
    """

    def __init__(self, hub: ControllerHub, signer_public_key: bytes) -> None:
        self._hub = hub
        self._public = Ed25519PublicKey.from_public_bytes(signer_public_key)
        self.received: list[dict] = []
        self.reject = False
        self.silent = False
        self.session: ControllerSession | None = None

    async def connect(self, controller_id: uuid.UUID, controller_code: str) -> None:
        self.session = ControllerSession(
            controller_id=controller_id,
            controller_code=controller_code,
            send=self._on_message,
        )
        await self._hub.register(self.session)

    async def _on_message(self, raw: str) -> None:
        message = json.loads(raw)
        if message.get("type") != "command":
            return
        self.received.append(message)
        if self.silent:
            return

        payload = message["payload"]
        try:
            self._public.verify(
                base64.b64decode(message["signature"]), canonical_bytes(payload)
            )
            verified = True
        except Exception:
            verified = False

        expired = payload["expires_at"] < int(time.time())
        opened = verified and not expired and not self.reject

        self._hub.resolve(
            self.session,
            {
                "type": "ack",
                "command_id": payload["command_id"],
                "result": "opened" if opened else "rejected",
                "detail": "ok" if opened else ("bad_signature" if not verified else "expired"),
                "relay_ms": payload["duration_ms"] if opened else 0,
                "uptime_ms": 1234,
            },
        )


@pytest_asyncio.fixture
async def world(services) -> World:
    return await World(services).build()


@pytest_asyncio.fixture
async def controller(services, signer_process, world) -> FakeController:
    device = FakeController(services.hub, signer_process["public_key"])
    await device.connect(world.controller_id, world.controller_code)
    return device


@pytest.fixture
def role_dsns(database_url: str) -> dict[str, str]:
    return {
        "app": APP_DSN,
        "audit": AUDIT_DSN,
        "migrate": MIGRATE_DSN,
        "superuser": SUPER_TEST_DSN,
    }
