"""Database privilege tests.

These do not exercise the application at all. They open a connection as each
role and try to do the thing that role must not be able to do. If a future
migration quietly widens a grant, one of these fails.

Everything here runs against a real PostgreSQL 16: privileges are not a thing
a mock can be wrong about in a useful way.
"""

from __future__ import annotations

import asyncpg
import pytest


async def _connect(dsn: str) -> asyncpg.Connection:
    return await asyncpg.connect(dsn)


# 1 -------------------------------------------------------------------------
async def test_app_role_cannot_delete_from_the_audit_log(role_dsns):
    conn = await _connect(role_dsns["app"])
    try:
        await conn.execute(
            "INSERT INTO acs.audit_log (event_type, outcome, actor_type) "
            "VALUES ('test.role', 'success', 'system')"
        )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("DELETE FROM acs.audit_log WHERE event_type = 'test.role'")
    finally:
        await conn.close()


# 2 -------------------------------------------------------------------------
async def test_app_role_cannot_update_the_audit_log(role_dsns):
    conn = await _connect(role_dsns["app"])
    try:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("UPDATE acs.audit_log SET outcome = 'success'")
    finally:
        await conn.close()


# 3 -------------------------------------------------------------------------
async def test_app_role_cannot_truncate_the_audit_log(role_dsns):
    conn = await _connect(role_dsns["app"])
    try:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("TRUNCATE acs.audit_log")
    finally:
        await conn.close()


# 4 -------------------------------------------------------------------------
async def test_app_role_can_append_and_read(role_dsns):
    """The two things it is supposed to be able to do still work."""
    conn = await _connect(role_dsns["app"])
    try:
        seq = await conn.fetchval(
            "INSERT INTO acs.audit_log (event_type, outcome, actor_type, detail) "
            "VALUES ('test.append', 'success', 'system', '{\"k\":1}'::jsonb) RETURNING seq"
        )
        assert seq > 0
        row = await conn.fetchrow("SELECT * FROM acs.audit_log WHERE seq = $1", seq)
        assert row["event_type"] == "test.append"
        assert len(bytes(row["row_hash"])) == 32
        assert len(bytes(row["prev_hash"])) == 32
    finally:
        await conn.close()


# 5 -------------------------------------------------------------------------
async def test_the_owner_is_blocked_by_the_trigger(role_dsns):
    """Layer two. Even the role that owns the table cannot rewrite a row."""
    conn = await _connect(role_dsns["migrate"])
    try:
        await conn.execute(
            "INSERT INTO acs.audit_log (event_type, outcome, actor_type) "
            "VALUES ('test.owner', 'success', 'system')"
        )
        with pytest.raises(asyncpg.PostgresError) as caught:
            await conn.execute(
                "UPDATE acs.audit_log SET outcome = 'failure' WHERE event_type = 'test.owner'"
            )
        assert "append-only" in str(caught.value)

        with pytest.raises(asyncpg.PostgresError) as caught:
            await conn.execute("DELETE FROM acs.audit_log WHERE event_type = 'test.owner'")
        assert "append-only" in str(caught.value)
    finally:
        await conn.close()


# 6 -------------------------------------------------------------------------
async def test_truncating_a_partition_is_blocked(role_dsns):
    """Partitions carry their own TRUNCATE guard, because a partitioned table
    cannot hold one."""
    conn = await _connect(role_dsns["migrate"])
    try:
        partition = await conn.fetchval(
            "SELECT c.relname FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'acs' AND c.relkind = 'r' AND c.relispartition "
            "  AND c.relname LIKE 'audit\\_log\\_%' "
            "ORDER BY c.relname DESC LIMIT 1"
        )
        assert partition, "expected at least one monthly partition"
        with pytest.raises(asyncpg.PostgresError) as caught:
            await conn.execute(f'TRUNCATE acs."{partition}"')
        assert "append-only" in str(caught.value)
    finally:
        await conn.close()


# 7 -------------------------------------------------------------------------
async def test_audit_role_cannot_read_users(role_dsns):
    """An operator browsing the audit trail is not holding a connection that
    can read password hashes."""
    conn = await _connect(role_dsns["audit"])
    try:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.fetch("SELECT * FROM acs.users")
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.fetch("SELECT * FROM acs.tokens")
    finally:
        await conn.close()


# 8 -------------------------------------------------------------------------
async def test_audit_role_cannot_write_operational_tables(role_dsns):
    conn = await _connect(role_dsns["audit"])
    try:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(
                "INSERT INTO acs.doors (code, name) VALUES ('x-door', 'X')"
            )
    finally:
        await conn.close()


# 9 -------------------------------------------------------------------------
async def test_app_role_holds_no_delete_anywhere(role_dsns):
    """Removal in this system is a flag, never a DELETE."""
    conn = await _connect(role_dsns["app"])
    try:
        for table in ("users", "devices", "doors", "controllers", "permissions", "tokens"):
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                await conn.execute(f"DELETE FROM acs.{table}")
    finally:
        await conn.close()


# 10 ------------------------------------------------------------------------
async def test_app_role_cannot_run_ddl(role_dsns):
    conn = await _connect(role_dsns["app"])
    try:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("CREATE TABLE acs.sneaky (id int)")
        with pytest.raises(asyncpg.PostgresError):
            await conn.execute("DROP TRIGGER deny_mutation ON acs.audit_log")
    finally:
        await conn.close()


# 11 ------------------------------------------------------------------------
async def test_app_role_cannot_escalate(role_dsns):
    conn = await _connect(role_dsns["app"])
    try:
        assert await conn.fetchval("SELECT current_user") == "acs_app"
        assert await conn.fetchval(
            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
        ) is False
        with pytest.raises(asyncpg.PostgresError):
            await conn.execute("SET ROLE acs_migrate")
        with pytest.raises(asyncpg.PostgresError):
            await conn.execute("ALTER ROLE acs_app SUPERUSER")
    finally:
        await conn.close()


# 12 ------------------------------------------------------------------------
async def test_app_role_cannot_forge_the_hash_chain(role_dsns):
    """Whatever the application sends for prev_hash and row_hash is discarded.

    The BEFORE INSERT trigger overwrites both from the row the database is
    about to store, so an application that has been told to lie about its own
    history cannot.
    """
    conn = await _connect(role_dsns["app"])
    try:
        forged = bytes(32)
        anchor = await conn.fetchval(
            "INSERT INTO acs.audit_log (event_type, outcome, actor_type) "
            "VALUES ('test.forge.anchor', 'success', 'system') RETURNING seq"
        )
        row = await conn.fetchrow(
            "INSERT INTO acs.audit_log "
            "  (event_type, outcome, actor_type, prev_hash, row_hash) "
            "VALUES ('test.forge', 'success', 'system', $1, $1) "
            "RETURNING prev_hash, row_hash",
            forged,
        )
        assert bytes(row["row_hash"]) != forged
        assert bytes(row["prev_hash"]) != forged

        # Verified from this test's own anchor. Other tests in the suite break
        # the chain on purpose, and a broken chain stays broken - that is the
        # property being demonstrated, not a flaw in this one.
        status = await conn.fetchrow(
            "SELECT * FROM acs.verify_audit_chain($1)", anchor
        )
        assert status["chain_ok"] is True
    finally:
        await conn.close()
