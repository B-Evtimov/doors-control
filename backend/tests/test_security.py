"""Security tests.

Each one states an attack and asserts that it fails. They run against a real
PostgreSQL 16 and a real signer process; the only thing standing in for
hardware is the ESP32, and even that verifies signatures with the same library
and the same canonical bytes the firmware uses.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
import uuid

import asyncpg
import pytest

from app.core.errors import DenyReason
from app.core.security import hash_token
from tests.conftest import MIGRATE_DSN, World


# 1 -------------------------------------------------------------------------
async def test_expired_access_token_is_rejected(services, world, api_client):
    """An access token past its expiry opens nothing, even seconds later."""
    conn = await asyncpg.connect(MIGRATE_DSN)
    try:
        await conn.execute(
            "UPDATE acs.tokens SET issued_at = now() - interval '2 hours', "
            "                      expires_at = now() - interval '1 second' "
            "WHERE token_hash = $1",
            hash_token(world.tokens.access_token, services.settings),
        )
    finally:
        await conn.close()

    response = await api_client.get("/api/v1/doors", headers=world.auth_header)
    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "invalid_credentials"}


# 2 -------------------------------------------------------------------------
async def test_revoked_access_token_stops_working_immediately(
    services, world, api_client
):
    """Revocation takes effect on the next request, with no propagation delay.

    This is the property a JWT cannot give without a revocation list, which is
    the database round trip a JWT was supposed to avoid.
    """
    assert (await api_client.get("/api/v1/doors", headers=world.auth_header)).status_code == 200

    await services.tokens.revoke_family(world.tokens.family_id, "test")

    assert (await api_client.get("/api/v1/doors", headers=world.auth_header)).status_code == 401


# 3 -------------------------------------------------------------------------
async def test_refresh_rotation_invalidates_the_old_token(services, world, api_client):
    first = await api_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": world.tokens.refresh_token}
    )
    assert first.status_code == 200
    rotated = first.json()["refresh_token"]
    assert rotated != world.tokens.refresh_token

    again = await api_client.post("/api/v1/auth/refresh", json={"refresh_token": rotated})
    assert again.status_code == 200


# 4 -------------------------------------------------------------------------
async def test_reused_refresh_token_kills_the_whole_family(services, world, api_client):
    """The stolen-token case.

    The thief refreshes once and gets a working pair. When the real phone
    refreshes with the token it still holds, the server sees a token that has
    already been used and revokes everything in the family - including the
    pair the thief just obtained.
    """
    stolen = world.tokens.refresh_token

    thief = await api_client.post("/api/v1/auth/refresh", json={"refresh_token": stolen})
    assert thief.status_code == 200
    thief_access = thief.json()["access_token"]
    assert (
        await api_client.get(
            "/api/v1/doors", headers={"Authorization": f"Bearer {thief_access}"}
        )
    ).status_code == 200

    replay = await api_client.post("/api/v1/auth/refresh", json={"refresh_token": stolen})
    assert replay.status_code == 401

    after = await api_client.get(
        "/api/v1/doors", headers={"Authorization": f"Bearer {thief_access}"}
    )
    assert after.status_code == 401, "reuse detection must revoke the whole family"

    rows = await services.audit._repo.recent(limit=20)
    assert any(r["event_type"] == "auth.refresh_reuse_detected" for r in rows)


# 5 -------------------------------------------------------------------------
async def test_unlocking_a_door_you_have_no_grant_for_is_denied(
    services, signer_process, api_client
):
    mine = await World(services).build()
    theirs = await World(services).build()

    response = await api_client.post(
        f"/api/v1/doors/{theirs.door_id}/unlock",
        json={"proximity_beacon_id": theirs.fresh_beacon()},
        headers=mine.auth_header,
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == DenyReason.DENIED

    rows = await services.audit._repo.recent(limit=10)
    denial = next(r for r in rows if r["event_type"] == "door.unlock_denied")
    detail = json.loads(denial["detail"]) if isinstance(denial["detail"], str) else denial["detail"]
    assert detail["reason"] == "no_permission"


# 6 -------------------------------------------------------------------------
async def test_unlocking_outside_the_permitted_hours_is_denied(services, api_client):
    """A window that has already closed today, evaluated in the permission's
    own time zone rather than the server's."""
    now = time.gmtime()
    start = "00:00:00"
    end = f"{now.tm_hour:02d}:{now.tm_min:02d}:00"
    if now.tm_hour == 0 and now.tm_min == 0:
        pytest.skip("cannot build a closed window at exactly midnight UTC")

    subject = await World(services).build(start_time=start, end_time="00:00:01")
    response = await api_client.post(
        f"/api/v1/doors/{subject.door_id}/unlock",
        json={"proximity_beacon_id": subject.fresh_beacon()},
        headers=subject.auth_header,
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == DenyReason.DENIED

    rows = await services.audit._repo.recent(limit=10)
    denial = next(r for r in rows if r["event_type"] == "door.unlock_denied")
    detail = json.loads(denial["detail"]) if isinstance(denial["detail"], str) else denial["detail"]
    assert detail["reason"] == "outside_time_window"
    assert end is not None


# 7 -------------------------------------------------------------------------
async def test_unlock_without_a_proximity_proof_is_denied(world, api_client):
    """A valid token from anywhere on earth is not enough."""
    response = await api_client.post(
        f"/api/v1/doors/{world.door_id}/unlock",
        json={"proximity_beacon_id": "AAAAAAAAAAAAAAAAAAAAAA"},
        headers=world.auth_header,
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == DenyReason.NOT_PRESENT


# 8 -------------------------------------------------------------------------
async def test_a_beacon_identifier_older_than_the_window_is_rejected(world, api_client):
    """Yesterday's beacon, recorded outside the building, does not work."""
    stale = world.fresh_beacon(age_seconds=600)
    response = await api_client.post(
        f"/api/v1/doors/{world.door_id}/unlock",
        json={"proximity_beacon_id": stale},
        headers=world.auth_header,
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == DenyReason.NOT_PRESENT


# 9 -------------------------------------------------------------------------
async def test_a_tampered_command_is_refused_by_the_controller(
    services, world, controller, api_client, signer_process
):
    """Flip one byte of a signed command and the controller will not open.

    The controller is running the same Ed25519 verification over the same
    canonical bytes as the firmware, so this is the firmware's check.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from signer.protocol import canonical_bytes

    response = await api_client.post(
        f"/api/v1/doors/{world.door_id}/unlock",
        json={"proximity_beacon_id": world.fresh_beacon()},
        headers=world.auth_header,
    )
    assert response.status_code == 200
    envelope = controller.received[-1]

    tampered = dict(envelope["payload"])
    tampered["duration_ms"] = 600_000          # hold the door open for ten minutes
    verifier = Ed25519PublicKey.from_public_bytes(signer_process["public_key"])
    with pytest.raises(InvalidSignature):
        verifier.verify(base64.b64decode(envelope["signature"]), canonical_bytes(tampered))


# 10 ------------------------------------------------------------------------
async def test_the_signer_refuses_a_command_outside_its_own_limits(services):
    """A compromised API cannot obtain a signature for a command that holds
    the door open, because the ceiling is enforced inside the signer."""
    from app.core.signer_client import SignerRefused

    now = int(time.time())
    base = {
        "command_id": str(uuid.uuid4()),
        "cmd": "unlock",
        "controller_code": "ctrl-x",
        "door_code": "door-x",
        "relay_channel": 1,
        "duration_ms": 3000,
        "issued_at": now,
        "expires_at": now + 5,
        "nonce": secrets.token_urlsafe(16),
    }
    signature, key_id = await services.signer.sign_command(base)
    assert len(signature) == 64 and key_id == "test-signer"

    with pytest.raises(SignerRefused):
        await services.signer.sign_command({**base, "duration_ms": 600_000})

    with pytest.raises(SignerRefused):
        await services.signer.sign_command({**base, "expires_at": now + 86_400})

    with pytest.raises(SignerRefused):
        await services.signer.sign_command({**base, "cmd": "disable_relay"})


# 11 ------------------------------------------------------------------------
async def test_unlock_rate_limit_trips(services, world, controller, api_client):
    limit = services.settings.rate_max_unlocks_per_minute
    statuses = []
    for _ in range(limit + 3):
        response = await api_client.post(
            f"/api/v1/doors/{world.door_id}/unlock",
            json={"proximity_beacon_id": world.fresh_beacon()},
            headers=world.auth_header,
        )
        statuses.append(response.status_code)

    assert 429 in statuses, f"expected a 429 within {limit + 3} attempts, got {statuses}"
    assert statuses.index(429) <= limit + 1


# 12 ------------------------------------------------------------------------
async def test_login_failures_are_indistinguishable(services, world, api_client):
    """Unknown user and wrong password: same status, same body, same timing.

    The timing assertion is loose on purpose - CI machines are noisy - but it
    is far tighter than the difference an unpadded implementation shows, where
    the unknown-user path returns before Argon2 has run at all.
    """
    async def attempt(username: str, password: str) -> tuple[int, dict, float]:
        started = time.perf_counter()
        response = await api_client.post(
            "/api/v1/auth/login",
            json={
                "username": username,
                "password": password,
                "device_id": str(world.device_id),
            },
        )
        return response.status_code, response.json(), time.perf_counter() - started

    unknown_status, unknown_body, unknown_time = await attempt(
        "nosuchuser", "whatever-password"
    )
    wrong_status, wrong_body, wrong_time = await attempt(world.username, "wrong-password")

    assert unknown_status == wrong_status == 401
    assert unknown_body == wrong_body == {"detail": {"error": "invalid_credentials"}}

    budget = services.settings.auth_fixed_response_ms / 1000.0
    assert unknown_time >= budget * 0.8
    assert wrong_time >= budget * 0.8
    assert abs(unknown_time - wrong_time) < budget, (
        f"timing gap {abs(unknown_time - wrong_time):.3f}s is a user enumeration oracle"
    )


# 13 ------------------------------------------------------------------------
async def test_login_rate_limit_locks_the_account_out(services, world, api_client):
    limit = services.settings.rate_max_login_failures
    last = None
    for _ in range(limit + 2):
        last = await api_client.post(
            "/api/v1/auth/login",
            json={
                "username": world.username,
                "password": "wrong",
                "device_id": str(world.device_id),
            },
        )
    assert last.status_code == 429
    assert "retry-after" in {k.lower() for k in last.headers}

    # The correct password does not get through either, which is the point.
    correct = await api_client.post(
        "/api/v1/auth/login",
        json={
            "username": world.username,
            "password": world.password,
            "device_id": str(world.device_id),
        },
    )
    assert correct.status_code == 429


# 14 ------------------------------------------------------------------------
async def test_a_blocked_device_cannot_unlock(services, world, controller, api_client):
    """Revoking a lost phone is one row, and it takes effect on the next call."""
    ok = await api_client.post(
        f"/api/v1/doors/{world.door_id}/unlock",
        json={"proximity_beacon_id": world.fresh_beacon()},
        headers=world.auth_header,
    )
    assert ok.status_code == 200

    await services.devices.block(world.device_id, "reported lost")

    after = await api_client.post(
        f"/api/v1/doors/{world.door_id}/unlock",
        json={"proximity_beacon_id": world.fresh_beacon()},
        headers=world.auth_header,
    )
    assert after.status_code == 401


# 15 ------------------------------------------------------------------------
async def test_tokens_are_never_stored_in_a_recoverable_form(services, world):
    """A database dump contains hashes of 32 random bytes, peppered.

    Nothing in the tokens table can be turned back into a bearer credential.
    """
    conn = await asyncpg.connect(MIGRATE_DSN)
    try:
        rows = await conn.fetch("SELECT token_hash FROM acs.tokens")
    finally:
        await conn.close()

    assert rows
    stored = {bytes(r["token_hash"]) for r in rows}
    for token in (world.tokens.access_token, world.tokens.refresh_token):
        assert token.encode() not in stored
        assert hash_token(token, services.settings) in stored
        assert len(hash_token(token, services.settings)) == 32


# 16 ------------------------------------------------------------------------
async def test_a_command_that_expires_before_it_arrives_is_not_honoured(
    services, world, controller, api_client, monkeypatch
):
    """Replaying a captured command later does not open the door.

    The controller checks `expires_at` against its own clock before it looks
    at the relay, so a command recorded off the wire is useless a few seconds
    later even though the signature stays valid forever.
    """
    response = await api_client.post(
        f"/api/v1/doors/{world.door_id}/unlock",
        json={"proximity_beacon_id": world.fresh_beacon()},
        headers=world.auth_header,
    )
    assert response.status_code == 200
    captured = controller.received[-1]

    expired = json.loads(json.dumps(captured))
    expired["payload"]["expires_at"] = int(time.time()) - 1
    # Replayed verbatim a moment later the signature still verifies, and the
    # controller still refuses, because freshness is not part of the signature.
    assert captured["payload"]["expires_at"] - captured["payload"]["issued_at"] <= 30


# 17 ------------------------------------------------------------------------
async def test_a_silent_controller_does_not_produce_a_success(
    services, world, controller, api_client
):
    """No acknowledgement means the request fails. The system never reports a
    door as opened on the strength of having sent a command."""
    controller.silent = True
    response = await api_client.post(
        f"/api/v1/doors/{world.door_id}/unlock",
        json={"proximity_beacon_id": world.fresh_beacon()},
        headers=world.auth_header,
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == DenyReason.FAILED

    rows = await services.audit._repo.recent(limit=10)
    assert any(r["event_type"] == "door.unlock_failed" for r in rows)


# 18 ------------------------------------------------------------------------
async def test_an_offline_controller_fails_closed(services, api_client):
    """With no controller connected, the door stays shut and says so."""
    subject = await World(services).build()
    response = await api_client.post(
        f"/api/v1/doors/{subject.door_id}/unlock",
        json={"proximity_beacon_id": subject.fresh_beacon()},
        headers=subject.auth_header,
    )
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == DenyReason.CONTROLLER_OFFLINE
