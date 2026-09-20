-- ============================================================================
-- 002_schema.sql
--
-- The schema itself plus the enumerated types. Everything lives in "acs";
-- nothing is created in public, so a mistake in search_path resolves to
-- nothing rather than to someone else's table.
-- ============================================================================

\set ON_ERROR_STOP on

CREATE SCHEMA IF NOT EXISTS acs AUTHORIZATION acs_migrate;

-- gen_random_uuid() and sha256() are built in since PostgreSQL 13 and 11
-- respectively, so no extension is required for either.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
                   WHERE t.typname = 'actor_type' AND n.nspname = 'acs') THEN
        CREATE TYPE acs.actor_type AS ENUM
            ('user', 'device', 'controller', 'admin', 'system', 'anonymous');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
                   WHERE t.typname = 'audit_outcome' AND n.nspname = 'acs') THEN
        CREATE TYPE acs.audit_outcome AS ENUM ('success', 'failure', 'denied');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
                   WHERE t.typname = 'token_kind' AND n.nspname = 'acs') THEN
        CREATE TYPE acs.token_kind AS ENUM ('access', 'refresh');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
                   WHERE t.typname = 'attestation_status' AND n.nspname = 'acs') THEN
        CREATE TYPE acs.attestation_status AS ENUM
            ('pending', 'verified', 'failed', 'exempt');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
                   WHERE t.typname = 'rate_subject' AND n.nspname = 'acs') THEN
        CREATE TYPE acs.rate_subject AS ENUM ('user', 'device', 'ip');
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS acs.schema_migrations (
    version      text        PRIMARY KEY,
    checksum     text        NOT NULL,
    applied_at   timestamptz NOT NULL DEFAULT now(),
    applied_by   text        NOT NULL DEFAULT current_user
);

COMMENT ON TABLE acs.schema_migrations IS
    'One row per applied migration file. The checksum is the SHA-256 of the '
    'file as applied; apply.sh refuses to continue if a already applied file '
    'has changed on disk.';
