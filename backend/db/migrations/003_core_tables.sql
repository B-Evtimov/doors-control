-- ============================================================================
-- 003_core_tables.sql
--
-- Operational tables. The audit log is deliberately not here: it has its own
-- migration because it has its own rules.
-- ============================================================================

\set ON_ERROR_STOP on

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS acs.users (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    username       text        NOT NULL,
    display_name   text        NOT NULL,
    -- Argon2id encoded string. The parameters live inside the hash, so raising
    -- the cost later does not invalidate existing passwords.
    password_hash  text        NOT NULL,
    is_admin       boolean     NOT NULL DEFAULT false,
    is_active      boolean     NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at  timestamptz,
    CONSTRAINT users_username_shape CHECK (username ~ '^[a-z0-9._-]{3,64}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_key
    ON acs.users (lower(username));

-- ---------------------------------------------------------------------------
-- devices - one row per enrolled phone
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS acs.devices (
    id                       uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                  uuid        NOT NULL
                                         REFERENCES acs.users (id) ON DELETE CASCADE,
    label                    text        NOT NULL,
    -- Raw Ed25519 public key generated inside the Android Keystore. The
    -- matching private key never leaves the phone's secure hardware.
    public_key               bytea       NOT NULL UNIQUE,
    platform                 text        NOT NULL DEFAULT 'android',
    app_version              text,
    attestation_status       acs.attestation_status NOT NULL DEFAULT 'pending',
    attestation_verified_at  timestamptz,
    -- Parsed attestation verdict: security level, boot state, integrity tokens.
    attestation_detail       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    is_blocked               boolean     NOT NULL DEFAULT false,
    blocked_reason           text,
    created_at               timestamptz NOT NULL DEFAULT now(),
    last_seen_at             timestamptz,
    CONSTRAINT devices_public_key_len CHECK (octet_length(public_key) = 32)
);

CREATE INDEX IF NOT EXISTS devices_user_id_idx ON acs.devices (user_id);
CREATE INDEX IF NOT EXISTS devices_active_idx
    ON acs.devices (user_id) WHERE NOT is_blocked;

-- ---------------------------------------------------------------------------
-- enrollment_codes - short lived one-time codes handed out by an admin
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS acs.enrollment_codes (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid        NOT NULL REFERENCES acs.users (id) ON DELETE CASCADE,
    -- SHA-256 of the code. The plaintext is shown to the admin once.
    code_hash      bytea       NOT NULL UNIQUE,
    created_by     uuid        REFERENCES acs.users (id),
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    used_by_device uuid        REFERENCES acs.devices (id),
    CONSTRAINT enrollment_code_hash_len CHECK (octet_length(code_hash) = 32)
);

CREATE INDEX IF NOT EXISTS enrollment_codes_open_idx
    ON acs.enrollment_codes (expires_at) WHERE used_at IS NULL;

-- ---------------------------------------------------------------------------
-- controllers - one row per ESP32 board
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS acs.controllers (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    code             text        NOT NULL UNIQUE,
    name             text        NOT NULL,
    -- Ed25519 public key burned in at provisioning time. The server checks the
    -- challenge response against this; there is no other way in.
    public_key       bytea       NOT NULL UNIQUE,
    -- Shared secret from which the rotating BLE beacon identifier is derived.
    -- The phone never sees it: it only reports identifiers it observed.
    beacon_key       bytea       NOT NULL,
    firmware_version text,
    is_blocked       boolean     NOT NULL DEFAULT false,
    blocked_reason   text,
    last_seen_at     timestamptz,
    last_ip          inet,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT controllers_public_key_len CHECK (octet_length(public_key) = 32),
    CONSTRAINT controllers_beacon_key_len CHECK (octet_length(beacon_key) = 32)
);

-- ---------------------------------------------------------------------------
-- doors
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS acs.doors (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    code           text        NOT NULL UNIQUE,
    name           text        NOT NULL,
    location       text,
    controller_id  uuid        REFERENCES acs.controllers (id) ON DELETE SET NULL,
    relay_channel  smallint    NOT NULL DEFAULT 1,
    -- Fixed pulse length. Kept in the database so an operator can shorten it,
    -- but the firmware clamps it as well: the controller never trusts a number
    -- it is sent further than its own ceiling.
    unlock_seconds smallint    NOT NULL DEFAULT 3,
    is_active      boolean     NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT doors_unlock_seconds_sane CHECK (unlock_seconds BETWEEN 1 AND 10),
    CONSTRAINT doors_relay_channel_sane  CHECK (relay_channel BETWEEN 1 AND 4)
);

CREATE INDEX IF NOT EXISTS doors_controller_idx ON acs.doors (controller_id);

-- ---------------------------------------------------------------------------
-- permissions - user x door x time window
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS acs.permissions (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES acs.users (id) ON DELETE CASCADE,
    door_id      uuid        NOT NULL REFERENCES acs.doors (id) ON DELETE CASCADE,
    valid_from   timestamptz NOT NULL DEFAULT now(),
    valid_until  timestamptz,
    -- Bit 0 = Monday ... bit 6 = Sunday. 127 means every day.
    weekday_mask smallint    NOT NULL DEFAULT 127,
    start_time   time        NOT NULL DEFAULT '00:00:00',
    end_time     time        NOT NULL DEFAULT '23:59:59',
    -- Windows are evaluated in this zone, not in the server's zone, so a
    -- daylight saving change does not silently widen or narrow access.
    time_zone    text        NOT NULL DEFAULT 'Europe/Sofia',
    is_active    boolean     NOT NULL DEFAULT true,
    created_by   uuid        REFERENCES acs.users (id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT permissions_weekday_mask_range CHECK (weekday_mask BETWEEN 0 AND 127),
    CONSTRAINT permissions_window_order CHECK (start_time < end_time),
    CONSTRAINT permissions_validity_order
        CHECK (valid_until IS NULL OR valid_until > valid_from)
);

-- A user may hold at most one live grant per door. Historic rows stay for the
-- record with is_active = false.
CREATE UNIQUE INDEX IF NOT EXISTS permissions_active_unique
    ON acs.permissions (user_id, door_id) WHERE is_active;

CREATE INDEX IF NOT EXISTS permissions_door_idx ON acs.permissions (door_id) WHERE is_active;

-- ---------------------------------------------------------------------------
-- tokens - opaque, hashed, with families for reuse detection
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS acs.tokens (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Every refresh rotation stays in the same family. Detecting a replay of
    -- any member kills the whole family at once.
    family_id      uuid        NOT NULL,
    user_id        uuid        NOT NULL REFERENCES acs.users (id) ON DELETE CASCADE,
    device_id      uuid        NOT NULL REFERENCES acs.devices (id) ON DELETE CASCADE,
    kind           acs.token_kind NOT NULL,
    -- SHA-256 of pepper || token. The token itself exists only on the phone.
    token_hash     bytea       NOT NULL UNIQUE,
    parent_id      uuid        REFERENCES acs.tokens (id) ON DELETE SET NULL,
    issued_at      timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    revoked_at     timestamptz,
    revoked_reason text,
    CONSTRAINT tokens_hash_len CHECK (octet_length(token_hash) = 32),
    CONSTRAINT tokens_expiry_order CHECK (expires_at > issued_at)
);

CREATE INDEX IF NOT EXISTS tokens_family_idx ON acs.tokens (family_id);
CREATE INDEX IF NOT EXISTS tokens_user_kind_idx ON acs.tokens (user_id, kind);
CREATE INDEX IF NOT EXISTS tokens_live_idx
    ON acs.tokens (expires_at) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- failed_attempts - the durable half of rate limiting
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS acs.failed_attempts (
    id           bigint       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subject_type acs.rate_subject NOT NULL,
    subject      text         NOT NULL,
    endpoint     text         NOT NULL,
    client_ip    inet,
    occurred_at  timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS failed_attempts_lookup_idx
    ON acs.failed_attempts (subject_type, subject, occurred_at DESC);
