-- ============================================================================
-- 005_audit_chain.sql
--
-- The tamper evidence. Three things live here:
--
--   audit_payload()      the canonical byte serialisation of a row. Both the
--                        writer and the verifier call it, so there is exactly
--                        one definition of "what this row says".
--   audit_hash_chain()   BEFORE INSERT trigger. SECURITY DEFINER, so the hash
--                        is computed with the schema owner's privileges from
--                        the row the database is about to store - not from
--                        whatever the application claims the hash should be.
--                        The application cannot set prev_hash or row_hash:
--                        whatever it sends is overwritten here.
--   verify_audit_chain() walks the chain and returns the first row that does
--                        not add up.
--
-- Serialisation: the trigger takes a transaction level advisory lock before
-- reading the current head. Two concurrent inserts would otherwise both read
-- the same predecessor and produce a fork.
-- ============================================================================

\set ON_ERROR_STOP on

-- Arbitrary but fixed. Every audit insert contends on this one key; the
-- critical section is a single indexed read plus a hash.
CREATE OR REPLACE FUNCTION acs.audit_chain_lock_key()
RETURNS bigint LANGUAGE sql IMMUTABLE PARALLEL SAFE AS
$$ SELECT 7734120126::bigint $$;

CREATE OR REPLACE FUNCTION acs.audit_genesis_hash()
RETURNS bytea LANGUAGE sql IMMUTABLE PARALLEL SAFE AS
$$ SELECT '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea $$;

-- ---------------------------------------------------------------------------
-- Canonical serialisation
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION acs.audit_payload(
    p_seq           bigint,
    p_occurred_at   timestamptz,
    p_event_type    text,
    p_outcome       acs.audit_outcome,
    p_actor_type    acs.actor_type,
    p_actor_id      uuid,
    p_device_id     uuid,
    p_door_id       uuid,
    p_controller_id uuid,
    p_client_ip     inet,
    p_detail        jsonb
) RETURNS bytea
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS
$$
    SELECT convert_to(
        concat_ws(E'\x1f',
            p_seq::text,
            -- Fixed UTC representation: the same instant must serialise the
            -- same way whatever TimeZone the verifying session happens to use.
            to_char(p_occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            p_event_type,
            p_outcome::text,
            p_actor_type::text,
            coalesce(p_actor_id::text, ''),
            coalesce(p_device_id::text, ''),
            coalesce(p_door_id::text, ''),
            coalesce(p_controller_id::text, ''),
            coalesce(host(p_client_ip), ''),
            coalesce(p_detail::text, '')
        ), 'UTF8')
$$;

COMMENT ON FUNCTION acs.audit_payload IS
    'Canonical bytes hashed into row_hash. Changing this function invalidates '
    'every existing chain, so it is versioned by migration and never edited '
    'in place: add a new migration that rebuilds the chain instead.';

-- ---------------------------------------------------------------------------
-- Guards
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION acs.deny_mutation()
RETURNS trigger LANGUAGE plpgsql AS
$$
BEGIN
    RAISE EXCEPTION
        'acs.audit_log is append-only: % denied on seq %',
        TG_OP, coalesce(OLD.seq::text, '?')
        USING ERRCODE = 'restrict_violation',
              HINT = 'Retention is done by detaching whole partitions.';
END
$$;

CREATE OR REPLACE FUNCTION acs.deny_truncate()
RETURNS trigger LANGUAGE plpgsql AS
$$
BEGIN
    RAISE EXCEPTION 'acs.audit_log is append-only: TRUNCATE denied on %',
        TG_TABLE_NAME
        USING ERRCODE = 'restrict_violation';
END
$$;

-- ---------------------------------------------------------------------------
-- The chain itself
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION acs.audit_hash_chain()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = acs, pg_catalog
AS $$
DECLARE
    v_prev bytea;
BEGIN
    -- Lazily create the partition this row belongs in, so a missed cron run
    -- can never turn into a lost audit event.
    PERFORM acs.ensure_audit_partition(NEW.occurred_at::date);

    PERFORM pg_advisory_xact_lock(acs.audit_chain_lock_key());

    SELECT row_hash INTO v_prev
    FROM acs.audit_log
    ORDER BY seq DESC
    LIMIT 1;

    v_prev := coalesce(v_prev, acs.audit_genesis_hash());

    NEW.prev_hash := v_prev;
    NEW.row_hash := sha256(
        acs.audit_payload(
            NEW.seq, NEW.occurred_at, NEW.event_type, NEW.outcome,
            NEW.actor_type, NEW.actor_id, NEW.device_id, NEW.door_id,
            NEW.controller_id, NEW.client_ip, NEW.detail
        ) || v_prev
    );

    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION acs.audit_hash_chain() FROM PUBLIC;

DROP TRIGGER IF EXISTS audit_hash_chain ON acs.audit_log;
CREATE TRIGGER audit_hash_chain
    BEFORE INSERT ON acs.audit_log
    FOR EACH ROW EXECUTE FUNCTION acs.audit_hash_chain();

DROP TRIGGER IF EXISTS deny_mutation ON acs.audit_log;
CREATE TRIGGER deny_mutation
    BEFORE UPDATE OR DELETE ON acs.audit_log
    FOR EACH ROW EXECUTE FUNCTION acs.deny_mutation();

-- ---------------------------------------------------------------------------
-- Verification
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION acs.verify_audit_chain(p_from_seq bigint DEFAULT 0)
RETURNS TABLE (
    chain_ok         boolean,
    rows_checked     bigint,
    first_bad_seq    bigint,
    first_bad_reason text
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    r          record;
    v_prev     bytea;
    v_expected bytea;
    v_count    bigint := 0;
    v_bad      bigint := NULL;
    v_reason   text   := NULL;
BEGIN
    IF p_from_seq <= 0 THEN
        v_prev := acs.audit_genesis_hash();
    ELSE
        SELECT row_hash INTO v_prev
        FROM acs.audit_log WHERE seq < p_from_seq
        ORDER BY seq DESC LIMIT 1;
        v_prev := coalesce(v_prev, acs.audit_genesis_hash());
    END IF;

    FOR r IN
        SELECT * FROM acs.audit_log WHERE seq >= p_from_seq ORDER BY seq
    LOOP
        v_count := v_count + 1;

        IF r.prev_hash IS DISTINCT FROM v_prev THEN
            v_bad := r.seq;
            v_reason := 'prev_hash does not match the preceding row: a row was '
                        'removed, reordered, or inserted out of band';
            EXIT;
        END IF;

        v_expected := sha256(
            acs.audit_payload(
                r.seq, r.occurred_at, r.event_type, r.outcome, r.actor_type,
                r.actor_id, r.device_id, r.door_id, r.controller_id,
                r.client_ip, r.detail
            ) || v_prev
        );

        IF r.row_hash IS DISTINCT FROM v_expected THEN
            v_bad := r.seq;
            v_reason := 'row_hash does not match the row contents: this row was '
                        'modified after it was written';
            EXIT;
        END IF;

        v_prev := r.row_hash;
    END LOOP;

    RETURN QUERY SELECT (v_bad IS NULL), v_count, v_bad, v_reason;
END
$$;

COMMENT ON FUNCTION acs.verify_audit_chain(bigint) IS
    'Walks the chain from p_from_seq and returns the first row that does not '
    'verify. Detects edits, deletions and reordering anywhere except at the '
    'very end of the chain - truncating the tail is caught by comparing '
    'audit_chain_head() against an externally anchored value.';

-- The head is what an external witness anchors. Publishing (seq, row_hash)
-- somewhere the database administrator does not control turns "delete the last
-- N rows" from undetectable into obvious.
CREATE OR REPLACE FUNCTION acs.audit_chain_head()
RETURNS TABLE (seq bigint, occurred_at timestamptz, row_hash bytea)
LANGUAGE sql STABLE AS
$$
    SELECT a.seq, a.occurred_at, a.row_hash
    FROM acs.audit_log a ORDER BY a.seq DESC LIMIT 1
$$;

-- Bootstrap the current and next month.
SELECT acs.ensure_audit_partitions_ahead(2);
