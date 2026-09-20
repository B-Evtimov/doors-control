-- ============================================================================
-- 001_roles.sql
--
-- Cluster level bootstrap. This is the only migration that needs a role with
-- CREATEROLE; everything after it runs as acs_migrate.
--
-- Three roles, three jobs, no overlap:
--
--   acs_migrate  owns the schema and is the only role allowed to run DDL.
--                Never used by a running service.
--   acs_app      the public API. Reads and writes operational tables.
--                On audit_log it has INSERT and SELECT and nothing else, so a
--                remote code execution bug in the API still cannot erase the
--                record of what it did.
--   acs_audit    the audit reader/writer used by the admin application.
--                Sees audit_log and nothing else - not users, not tokens.
--
-- Passwords come from psql variables set by apply.sh from the environment.
-- No password is ever written into this file.
-- ============================================================================

\set ON_ERROR_STOP on

-- psql does not expand :variables inside dollar quoted blocks, so the role
-- statements are generated and executed with \gexec. The password never
-- appears in this file, only the name of the variable apply.sh fills in.

SELECT 'CREATE ROLE acs_migrate LOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'acs_migrate')
\gexec

SELECT 'CREATE ROLE acs_app LOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'acs_app')
\gexec

SELECT 'CREATE ROLE acs_audit LOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'acs_audit')
\gexec

SELECT format('ALTER ROLE acs_migrate LOGIN PASSWORD %L', :'migrate_password') \gexec
SELECT format('ALTER ROLE acs_app   LOGIN PASSWORD %L', :'app_password')     \gexec
SELECT format('ALTER ROLE acs_audit LOGIN PASSWORD %L', :'audit_password')   \gexec

-- None of the three may hand its rights to anyone else.
ALTER ROLE acs_migrate NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE acs_app     NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE acs_audit   NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- None of the service roles may create objects anywhere, including in public.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE :"dbname" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"dbname" TO acs_migrate, acs_app, acs_audit;
-- Only the migration role may create objects in this database.
GRANT CREATE ON DATABASE :"dbname" TO acs_migrate;

-- A runaway query must not be able to pin the server. Overridable per session
-- by acs_migrate only, which is why the migration role gets a longer budget.
ALTER ROLE acs_app   SET statement_timeout = '10s';
ALTER ROLE acs_audit SET statement_timeout = '30s';
ALTER ROLE acs_app   SET idle_in_transaction_session_timeout = '15s';
ALTER ROLE acs_audit SET idle_in_transaction_session_timeout = '30s';

-- The application must never see rows it forgot to filter because of a stale
-- search_path pointing at a shadow table in public.
ALTER ROLE acs_app   SET search_path = acs;
ALTER ROLE acs_audit SET search_path = acs;
ALTER ROLE acs_migrate SET search_path = acs, public;
