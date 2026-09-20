"""The audit chain under attack.

The scenario is the worst realistic one: an attacker who has reached superuser
on the database server. Grants do not stop them and neither do triggers - a
superuser can set `session_replication_role = replica` and both stop firing.
What they cannot do is recompute the chain, because every row after the one
they edited commits to a hash they have just invalidated.
"""

from __future__ import annotations

import asyncpg


async def _insert(conn: asyncpg.Connection, event: str) -> int:
    return await conn.fetchval(
        "INSERT INTO acs.audit_log (event_type, outcome, actor_type, detail) "
        "VALUES ($1, 'success', 'system', '{}'::jsonb) RETURNING seq",
        event,
    )


async def test_a_healthy_chain_verifies(role_dsns):
    conn = await asyncpg.connect(role_dsns["app"])
    try:
        first = await _insert(conn, "chain.healthy.0")
        for i in range(1, 5):
            await _insert(conn, f"chain.healthy.{i}")
        # From this test's own first row: other tests in the suite tamper with
        # the log on purpose, and a broken chain stays broken - that is the
        # property being demonstrated.
        status = await conn.fetchrow("SELECT * FROM acs.verify_audit_chain($1)", first)
        assert status["chain_ok"] is True
        assert status["first_bad_seq"] is None
        assert status["rows_checked"] >= 5
    finally:
        await conn.close()


async def test_a_superuser_editing_a_row_is_detected(role_dsns):
    """The test the whole design exists for.

    Triggers off, one row edited, triggers back on. The row looks untouched;
    the chain does not.
    """
    app = await asyncpg.connect(role_dsns["app"])
    root = await asyncpg.connect(role_dsns["superuser"])
    try:
        first = await _insert(app, "chain.before")
        target = await _insert(app, "chain.target")
        await _insert(app, "chain.after")

        before = await app.fetchrow("SELECT * FROM acs.verify_audit_chain($1)", first)
        assert before["chain_ok"] is True

        # The attack: rewrite a denial so it reads as a success.
        await root.execute("SET session_replication_role = replica")
        await root.execute(
            "UPDATE acs.audit_log SET outcome = 'failure', "
            "detail = '{\"covered\":\"up\"}'::jsonb WHERE seq = $1",
            target,
        )
        await root.execute("SET session_replication_role = origin")

        after = await app.fetchrow("SELECT * FROM acs.verify_audit_chain($1)", first)
        assert after["chain_ok"] is False
        assert after["first_bad_seq"] == target
        assert "row_hash does not match" in after["first_bad_reason"]
    finally:
        await app.close()
        await root.close()


async def test_a_deleted_row_breaks_the_link(role_dsns):
    """Removing a row entirely is caught too: the next row's prev_hash points
    at something that is no longer there."""
    app = await asyncpg.connect(role_dsns["app"])
    root = await asyncpg.connect(role_dsns["superuser"])
    try:
        first = await _insert(app, "chain.delete.before")
        victim = await _insert(app, "chain.delete.victim")
        await _insert(app, "chain.delete.after")

        await root.execute("SET session_replication_role = replica")
        await root.execute("DELETE FROM acs.audit_log WHERE seq = $1", victim)
        await root.execute("SET session_replication_role = origin")

        status = await app.fetchrow("SELECT * FROM acs.verify_audit_chain($1)", first)
        assert status["chain_ok"] is False
        assert "prev_hash does not match" in status["first_bad_reason"]
    finally:
        await app.close()
        await root.close()


async def test_the_head_is_anchorable(role_dsns):
    """`audit_chain_head()` is what an external witness records, which is the
    only thing that catches truncation of the tail."""
    conn = await asyncpg.connect(role_dsns["app"])
    try:
        await _insert(conn, "chain.head")
        head = await conn.fetchrow("SELECT * FROM acs.audit_chain_head()")
        assert head is not None
        assert len(bytes(head["row_hash"])) == 32
    finally:
        await conn.close()
