-- ============================================================================
-- 004_audit_log.sql
--
-- The audit log is append-only. Not "the application only appends to it" -
-- append-only enforced by the database, on three independent layers:
--
--   1. Role grants          acs_app and acs_audit hold INSERT and SELECT.
--                           No UPDATE, no DELETE, no TRUNCATE. A compromised
--                           API process cannot express the statement.
--   2. Triggers             deny_mutation and deny_truncate raise an exception
--                           regardless of who is asking, including the table
--                           owner. Grants can be changed by a superuser in one
--                           statement; this layer makes that not enough.
--   3. Hash chain           every row carries the hash of its own content plus
--                           the hash of the row before it, computed inside the
--                           database by a SECURITY DEFINER trigger. Editing a
--                           row with the triggers disabled still breaks the
--                           chain from that row onward, and
--                           verify_audit_chain() points at the first bad one.
--
-- Partitioned by month so that retention is a DETACH, never a DELETE.
-- ============================================================================

\set ON_ERROR_STOP on

CREATE SEQUENCE IF NOT EXISTS acs.audit_seq AS bigint START 1;

CREATE TABLE IF NOT EXISTS acs.audit_log (
    seq           bigint      NOT NULL DEFAULT nextval('acs.audit_seq'),
    occurred_at   timestamptz NOT NULL DEFAULT now(),
    event_type    text        NOT NULL,
    outcome       acs.audit_outcome NOT NULL,
    actor_type    acs.actor_type    NOT NULL,
    actor_id      uuid,
    device_id     uuid,
    door_id       uuid,
    controller_id uuid,
    client_ip     inet,
    -- Free-form context. jsonb text output is canonical in PostgreSQL (keys
    -- sorted, whitespace normalised), which is what makes it safe to hash.
    detail        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    prev_hash     bytea       NOT NULL,
    row_hash      bytea       NOT NULL,
    PRIMARY KEY (seq, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- Deliberately no foreign keys. An audit row must survive the deletion of the
-- user, device or door it talks about; that is half the point of keeping it.

COMMENT ON TABLE acs.audit_log IS
    'Append-only, hash chained, partitioned by month. Never UPDATE or DELETE '
    'a row here: use retention by partition detach. See verify_audit_chain().';

COMMENT ON COLUMN acs.audit_log.prev_hash IS
    'row_hash of the row with the next lower seq, or 32 zero bytes for the '
    'first row. Set by trigger, never by the application.';

-- ---------------------------------------------------------------------------
-- Partition management
-- ---------------------------------------------------------------------------

-- TRUNCATE triggers cannot be attached to a partitioned table, only to its
-- partitions, so every partition gets its own guard at creation time.
CREATE OR REPLACE FUNCTION acs.ensure_audit_partition(p_month date)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
    v_start date := date_trunc('month', p_month)::date;
    v_end   date := (date_trunc('month', p_month) + interval '1 month')::date;
    v_name  text := format('audit_log_%s', to_char(v_start, 'YYYY_MM'));
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'acs' AND c.relname = v_name
    ) THEN
        EXECUTE format(
            'CREATE TABLE acs.%I PARTITION OF acs.audit_log '
            'FOR VALUES FROM (%L) TO (%L)', v_name, v_start, v_end);

        EXECUTE format(
            'CREATE TRIGGER deny_truncate BEFORE TRUNCATE ON acs.%I '
            'FOR EACH STATEMENT EXECUTE FUNCTION acs.deny_truncate()', v_name);

        EXECUTE format(
            'REVOKE UPDATE, DELETE, TRUNCATE ON acs.%I FROM PUBLIC', v_name);
        EXECUTE format(
            'GRANT SELECT, INSERT ON acs.%I TO acs_app, acs_audit', v_name);
    END IF;

    RETURN v_name;
END
$$;

COMMENT ON FUNCTION acs.ensure_audit_partition(date) IS
    'Creates the monthly partition for the given month if it does not exist, '
    'attaches the TRUNCATE guard and applies grants. Idempotent.';

-- Keeps the current month and the next one alive. Call it from cron; the
-- insert path also calls it lazily so a missed cron run cannot lose an event.
CREATE OR REPLACE FUNCTION acs.ensure_audit_partitions_ahead(p_months int DEFAULT 2)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    i int;
BEGIN
    FOR i IN 0 .. greatest(p_months - 1, 0) LOOP
        PERFORM acs.ensure_audit_partition((current_date + (i || ' month')::interval)::date);
    END LOOP;
END
$$;
