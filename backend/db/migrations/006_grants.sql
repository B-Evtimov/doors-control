-- ============================================================================
-- 006_grants.sql
--
-- Least privilege, written out explicitly rather than inherited from a
-- framework's idea of what an application needs.
--
-- Two rules worth stating out loud:
--   * no role holds DELETE on anything. Removal is a flag, not a statement.
--   * acs_app holds INSERT and SELECT on audit_log and nothing more. That is
--     the whole point: the process that handles requests from the internet
--     cannot express an UPDATE or a DELETE against the record of what it did.
-- ============================================================================

\set ON_ERROR_STOP on

REVOKE ALL ON SCHEMA acs FROM PUBLIC;
GRANT USAGE ON SCHEMA acs TO acs_app, acs_audit;

REVOKE ALL ON ALL TABLES IN SCHEMA acs FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA acs FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA acs FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- acs_app - the public API
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE ON
    acs.users,
    acs.devices,
    acs.enrollment_codes,
    acs.controllers,
    acs.doors,
    acs.permissions,
    acs.tokens
TO acs_app;

GRANT SELECT, INSERT ON acs.failed_attempts TO acs_app;
GRANT USAGE ON SEQUENCE acs.failed_attempts_id_seq TO acs_app;

-- The audit table. Note what is absent.
GRANT SELECT, INSERT ON acs.audit_log TO acs_app;
GRANT USAGE ON SEQUENCE acs.audit_seq TO acs_app;

-- Helpers that verify_audit_chain() calls internally. They are listed
-- explicitly because REVOKE ALL ON ALL FUNCTIONS above stripped them.
GRANT EXECUTE ON FUNCTION acs.audit_genesis_hash() TO acs_app, acs_audit;
GRANT EXECUTE ON FUNCTION acs.audit_chain_lock_key() TO acs_app, acs_audit;
GRANT EXECUTE ON FUNCTION acs.audit_payload(
    bigint, timestamptz, text, acs.audit_outcome, acs.actor_type,
    uuid, uuid, uuid, uuid, inet, jsonb) TO acs_app, acs_audit;

GRANT EXECUTE ON FUNCTION acs.verify_audit_chain(bigint) TO acs_app;
GRANT EXECUTE ON FUNCTION acs.audit_chain_head() TO acs_app;
GRANT EXECUTE ON FUNCTION acs.ensure_audit_partition(date) TO acs_app;
GRANT EXECUTE ON FUNCTION acs.ensure_audit_partitions_ahead(int) TO acs_app;

-- ---------------------------------------------------------------------------
-- acs_audit - the audit reader used by the admin application
--
-- It can read and append the log and see nothing else. An operator browsing
-- the audit trail is not holding a connection that can read password hashes.
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT ON acs.audit_log TO acs_audit;
GRANT USAGE ON SEQUENCE acs.audit_seq TO acs_audit;
GRANT EXECUTE ON FUNCTION acs.verify_audit_chain(bigint) TO acs_audit;
GRANT EXECUTE ON FUNCTION acs.audit_chain_head() TO acs_audit;
GRANT EXECUTE ON FUNCTION acs.ensure_audit_partition(date) TO acs_audit;
GRANT EXECUTE ON FUNCTION acs.ensure_audit_partitions_ahead(int) TO acs_audit;

-- Spelled out even though REVOKE ALL above already covers it, because this is
-- the line a future reader will look for.
REVOKE UPDATE, DELETE, TRUNCATE ON acs.audit_log FROM acs_app, acs_audit;
REVOKE DELETE ON ALL TABLES IN SCHEMA acs FROM acs_app, acs_audit;
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA acs FROM acs_app, acs_audit;

-- ---------------------------------------------------------------------------
-- Defaults for objects created by later migrations
-- ---------------------------------------------------------------------------
ALTER DEFAULT PRIVILEGES FOR ROLE acs_migrate IN SCHEMA acs
    REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE acs_migrate IN SCHEMA acs
    GRANT SELECT, INSERT, UPDATE ON TABLES TO acs_app;
ALTER DEFAULT PRIVILEGES FOR ROLE acs_migrate IN SCHEMA acs
    GRANT USAGE ON SEQUENCES TO acs_app, acs_audit;

-- Migration role keeps ownership; it is not used by any running service.
ALTER SCHEMA acs OWNER TO acs_migrate;
