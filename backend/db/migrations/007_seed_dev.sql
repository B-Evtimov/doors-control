-- ============================================================================
-- 007_seed_dev.sql
--
-- Reference data only. No credentials, no keys, no real names.
--
-- This migration is applied by apply.sh only when ACS_SEED_DEV=1. It exists so
-- that a fresh checkout has something to look at, and so the test suite has a
-- known door to aim at. It creates no user and no password: the first admin is
-- created by backend/scripts/create_admin.py, which reads the password from a
-- prompt and never from a file.
-- ============================================================================

\set ON_ERROR_STOP on

INSERT INTO acs.controllers (code, name, public_key, beacon_key)
VALUES (
    'ctrl-demo-01',
    'Demo controller',
    -- Placeholder key material. Provisioning replaces both of these; the
    -- values here are all zeroes precisely so that nobody mistakes them for
    -- something usable.
    repeat('\000', 32)::bytea,
    repeat('\001', 32)::bytea
)
ON CONFLICT (code) DO NOTHING;

INSERT INTO acs.doors (code, name, location, controller_id, relay_channel, unlock_seconds)
SELECT 'door-demo-01', 'Demo door', 'Example site', c.id, 1, 3
FROM acs.controllers c WHERE c.code = 'ctrl-demo-01'
ON CONFLICT (code) DO NOTHING;
