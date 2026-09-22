# Evtimov Doors Control System

[![CI](https://github.com/B-Evtimov/doors-control/actions/workflows/ci.yml/badge.svg)](https://github.com/B-Evtimov/doors-control/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)

**A phone-only door access system where the server that opens the door cannot
forge the command, the app that runs it cannot rewrite the log, and a valid
token from the other side of the world is not enough.**

Android app, FastAPI backend in rootless containers, ESP32 controllers that
dial out and never listen. Unlock commands are signed by a process with no
network access. The audit log is append-only in three independent layers, and
tampering with a row that has already been written is provably detectable —
there is a test that performs the attack as a database superuser and asserts
that the row is named.

> **Status:** a reference implementation built as a portfolio project. The backend,
> database, firmware and Android app all build in CI, and the backend is covered by
> 34 tests against a real PostgreSQL 16. It has not been deployed to production
> hardware.

```mermaid
flowchart LR
    subgraph Phone["Android phone"]
        APP["Compose app"]
        KS["Keystore key<br/>StrongBox / TEE<br/>biometric gated"]
        BLE["BLE scanner"]
    end

    subgraph Host["Server - rootless Podman"]
        API["acs-api<br/>role: acs_app<br/>no DELETE anywhere"]
        SIGNER["acs-signer<br/>no network namespace<br/>holds the signing key"]
        ADMIN["acs-admin<br/>127.0.0.1, no DNS record"]
        DB[("PostgreSQL 16<br/>append-only<br/>hash-chained audit")]
    end

    subgraph Door["At the door"]
        ESP["ESP32-WROOM-32"]
        RELAY["Relay + fail-secure strike"]
        BEACON(("BLE beacon<br/>rotates every 30 s"))
    end

    APP -->|HTTPS, pinned| API
    ESP -->|outbound WSS, always open| API
    API -->|unix socket| SIGNER
    API --> DB
    ADMIN --> DB
    ESP --- RELAY
    ESP --- BEACON
    BEACON -. heard by .-> BLE
    APP --- KS
```

---

## Security design

This is the part worth reading. Every mechanism below exists because of a
specific attack, and each one says what it does not solve.

### Opaque tokens, and why there is no JWT anywhere

A JWT is valid because it verifies. That is the appeal — no database round
trip — and it is exactly wrong for a lock. There is no moment at which the
server can stop honouring one. To revoke a JWT early you keep a revocation
list and check it on every request, at which point the round trip is back and
what remains is a bearer credential whose contents the holder can read.

A phone is reported lost at 14:02 and must stop opening doors at 14:02, not at
14:17 when a fifteen-minute token happens to expire.

So the tokens here are 32 bytes of CSPRNG output with no structure. The
database stores `SHA-256(pepper || token)` and nothing else; the pepper lives
in the process environment, not in the database. Revocation is one `UPDATE`,
and the next request fails. A stolen dump contains hashes of 256-bit random
values — there is no dictionary to run against that.

SHA-256 rather than Argon2 for tokens is deliberate: the input already has 256
bits of entropy, so there is nothing to slow an attacker down about, and it
runs on every authenticated request. Argon2id is used for passwords, where the
input is a human-chosen string.

### Refresh rotation with reuse detection

Each login opens a token *family*. Refreshing mints a new pair in the same
family and marks the old refresh token used. **If a used refresh token appears
again, the entire family is revoked.**

The server cannot distinguish a legitimate retry after a lost response from a
thief replaying a copied token. Given that ambiguity, it assumes theft: the
honest user signs in again, which is an annoyance; the thief loses the session
they just obtained, which is the point.

`test_reused_refresh_token_kills_the_whole_family` plays this out — the thief
refreshes, gets a working token, and loses it the moment the real phone
refreshes.

### Proximity: a token is not a location

A valid token says the holder is authorised. It says nothing about where they
are standing. Malware with a live token can send a perfectly formed unlock
request from another continent.

Each controller advertises a rotating identifier:

```
beacon_id(slot) = HMAC-SHA256(beacon_key, "acs-beacon:v1" || slot)[:16]
slot            = floor(unix_seconds / 30)
```

The phone reports what it heard. The server recomputes the identifiers for the
slots covering the last 60 seconds and accepts only a match. **The phone's
clock is never consulted** — freshness comes from which slot the value belongs
to, so a manipulated clock cannot widen the window. The phone does not hold
the beacon key and cannot compute an identifier; it can only report having
been there.

*What this does not stop:* a BLE relay. Two radios, one at the door and one
near the phone, and the phone genuinely hears a current identifier. Bounding
that needs a round-trip time measurement, which needs a connectable
characteristic rather than a plain advertisement. It is on the roadmap and
recorded as residual risk T-11. What the beacon eliminates today is the remote
attack — the one that scales.

### The signing key lives in a process with no network

`acs-signer` runs in its own container with `Network=none`, a read-only root
filesystem, all capabilities dropped and exactly one way in: a Unix socket. It
answers two questions — "what is your public key" and "sign this command" —
and it validates the command before signing it. `duration_ms` at most 10
seconds, command lifetime at most 30 seconds, `cmd` must be `unlock`.

The split buys something specific. An attacker who owns the API container can
make the signer sign unlock commands *while they are there*, and gets nothing
that outlives that access. An attacker who owns a process holding the key can
mint commands forever, including for doors that are offline today and will
accept them tomorrow. Compromise of the API is bad; compromise of the key is
unrecoverable without reflashing every controller.

Because the ceiling is inside the signer, **a fully compromised API cannot
obtain a signature for a command that holds a door open for an hour** —
`test_the_signer_refuses_a_command_outside_its_own_limits`.

### Controllers dial out and never listen

The ESP32 opens a WSS connection and keeps it open. There is no port to scan
at the door, no inbound firewall rule, no NAT traversal and no port forwarding
for an installer to get wrong. The controller is not addressable.

It fails in the right direction too: if the link drops, the door stays locked.
No offline mode, no cached credential list, no local override — no button, no
keypad header, no serial command that opens the door. The only path to the
relay goes through a signature the firmware verified itself.

Before it touches the relay, the firmware checks that the command is for
*this* controller, that the Ed25519 signature verifies, that its clock is
actually synchronised, that `expires_at` has not passed, and that the
`command_id` is not one it has already honoured. It rebuilds the signed bytes
field by field in sorted key order rather than re-serialising what its JSON
parser produced, so a payload carrying an unknown field fails verification
instead of being accepted with that field ignored.

### The audit log is append-only in the database, not in the application

"The application only appends to it" is a habit, not a property. Three
independent layers make it a property:

1. **Role grants.** `acs_app` holds `INSERT` and `SELECT` on `audit_log`. No
   `UPDATE`, no `DELETE`, no `TRUNCATE`. Remote code execution in the API
   leaves the attacker holding a connection that cannot express the statement
   they want.
2. **Triggers.** `deny_mutation` and `deny_truncate` raise an exception
   whoever is asking — including `acs_migrate`, which owns the table. Grants
   can be changed by a superuser in one statement; this makes that not enough.
3. **Hash chain.** Every row stores the SHA-256 of its own canonical
   serialisation concatenated with the previous row's hash, computed by a
   `SECURITY DEFINER` BEFORE INSERT trigger **from the row the database is
   about to store**. Whatever the application sends for `prev_hash` and
   `row_hash` is overwritten — the application is not trusted to describe its
   own history.

A superuser defeats layers 1 and 2 with
`SET session_replication_role = replica`. They cannot defeat layer 3:

```
 chain_ok | rows_checked | first_bad_seq |                first_bad_reason
----------+--------------+---------------+------------------------------------------------
 f        |            2 |             2 | row_hash does not match the row contents: ...
```

That output is from `test_a_superuser_editing_a_row_is_detected`, which
disables the triggers, rewrites a denial to read as a success, turns them back
on, and asserts that `verify_audit_chain()` names the row.

*What the chain does not catch:* deleting rows from the **end** leaves a
shorter but internally consistent chain. `audit_chain_head()` exists so that
`(seq, row_hash)` can be published where the database administrator cannot
reach it, which turns tail truncation from invisible into obvious. That is
T-19, and it is a residual risk, not a solved one.

### Least privilege that is actually tested

No database role holds `DELETE` on any table. Removal is `is_active = false`,
`is_blocked = true`, `revoked_at = now()`. Audit retention is a partition
detach.

`acs_audit`, used by the admin application, can read and append `audit_log`
and nothing else — an operator browsing the trail is not holding a connection
that can read password hashes.

Twelve tests open connections as each role and try the thing that role must
not be able to do. If a future migration quietly widens a grant, one of them
fails.

### Attestation: two statements about the phone

`setIsStrongBoxBacked(true)` where the hardware has a secure element, falling
back to the TEE. The key is non-exportable, so the app itself only ever holds
a handle, and `setUserAuthenticationRequired(true)` with a 30-second window
means **the Keystore refuses to sign until the user has authenticated** — the
biometric prompt is a gate, not a dialog. `setInvalidatedByBiometricEnrollment(true)`
destroys the key if someone adds their own fingerprint to a stolen phone.

Key attestation says the private key is in secure hardware on a device with a
locked bootloader. Play Integrity says the app asking is the build that was
published, unmodified. They answer different questions, and both are required
in `strict` mode. The attestation challenge is issued by the server *before*
the key is generated, which is what stops a chain captured from one device
being replayed onto another enrolment.

Neither is a guarantee — both have been defeated on specific devices. What
they do is move phone cloning from "copy a file out of the app's data
directory" to "defeat the secure element", which is a different budget.

### Uniform failures, in body and in time

Every authentication failure returns the same body, the same status, and
within measurement noise the same elapsed time. Identical error strings alone
are not enough: a lookup that misses returns in a millisecond while a hit runs
Argon2, and that difference is a user-enumeration oracle. So the missing-user
path performs a dummy Argon2 verification, and every authentication response
is padded to a fixed budget.

`test_login_failures_are_indistinguishable` asserts both the identical body
and the timing.

### Rate limiting that survives a restart

Three subjects, because they fail differently: **user** stops a guessing run
against one account from any number of addresses, **device** stops one
compromised phone hammering doors, **ip** stops one host enumerating accounts.
Delay is exponential in recent failures and capped.

The counters are in the database, not in memory. An in-memory counter resets
when the container restarts, which is exactly what an attacker would arrange
if they could.

### Plain SQL migrations

`--autogenerate` compares ORM metadata against the live database. Triggers,
`SECURITY DEFINER`, role grants, partitioning and partial indexes are all
invisible to it — and it does not error on any of them. It emits a migration
that applies cleanly and quietly leaves the database without its triggers and
without its grants. A security control that can vanish without a failed build
is not a control.

The full table of what gets silently dropped is in
[`backend/db/README.md`](backend/db/README.md).

### The admin application is not on the internet

It can grant a person a door, revoke a device and read the whole trail. The
phone app can do none of those. They share a database and nothing else.

It binds to `127.0.0.1`, has no public hostname and no DNS record — not merely
protected from the internet, but not addressable from it. There is no name to
resolve and nothing in certificate transparency to find.

### No secrets in the repository

Every one comes from the process environment. [`.env.example`](.env.example)
lists all of them with empty values and a line explaining what each is for.
`config.h` for the firmware is generated, gitignored, and never committed.

---

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| Phone | Kotlin, Jetpack Compose, MVVM | `minSdk 29` because hardware key attestation is the point |
| Keys on device | Android Keystore, StrongBox → TEE | non-exportable, biometric-gated |
| Transport | Retrofit + OkHttp, certificate pinning with backup pins | pinned on the intermediate so renewal needs no app release |
| Backend | Python 3.12, FastAPI, fully async | |
| Database | PostgreSQL 16, asyncpg, raw SQL migrations | partitioning, triggers, `SECURITY DEFINER`, role grants |
| Signing | Ed25519 (`cryptography`), isolated process | 64-byte signatures, verifiable on an ESP32 in milliseconds |
| Passwords | Argon2id | |
| Controllers | ESP32-WROOM-32, Arduino framework, PlatformIO | |
| Controller link | WSS, outbound only, Ed25519 challenge-response | |
| Runtime | Rootless Podman, Quadlet systemd units | read-only, no capabilities, `no-new-privileges` |
| CI | GitHub Actions against a real PostgreSQL 16 | |

## Hardware

| Part | Notes |
|---|---|
| ESP32-WROOM-32, 38 pin | Wi-Fi and BLE on one chip; BLE is the proximity proof |
| Opto-isolated relay module | strike current never touches the ESP32 |
| **Fail-secure** electric strike, 12 V | no current means locked; a tripped breaker must not open the door |
| 1N4007 flyback diode | across the coil, cathode to +12 V |
| Separate 12 V supply | for the strike only, grounds tied at one point |
| Reed switch (optional) | door open/closed, reported to the audit log |
| Tamper switch (optional) | enclosure opened, reported to the audit log |

Wiring diagram and the five things that matter more than the pinout:
[`firmware/esp32/README.md`](firmware/esp32/README.md)

<p align="center"><img src="firmware/esp32/wiring.svg" alt="ESP32 controller wiring" width="720"></p>

---

## Getting started locally

Needs Python 3.12, PostgreSQL 16 and `psql`.

```bash
git clone <your-fork>
cd evtimov-doors-control

# 1. database
createdb acs
cd backend/db
export ACS_DB_NAME=acs
export ACS_BOOTSTRAP_DSN="postgresql://postgres@127.0.0.1/acs"
export ACS_MIGRATE_DB_DSN="postgresql://acs_migrate:dev-migrate@127.0.0.1/acs"
export ACS_DB_MIGRATE_PASSWORD=dev-migrate
export ACS_DB_APP_PASSWORD=dev-app
export ACS_DB_AUDIT_PASSWORD=dev-audit
./apply.sh

# 2. backend
cd ..
pip install -e ".[dev]"
cp ../.env.example ../.env          # then fill it in
python -m signer.keygen             # signer keypair
python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"  # token pepper

# 3. signer, then API
ACS_SIGNER_SOCKET=/tmp/acs-signer.sock \
ACS_SIGNER_PRIVATE_KEY=<from keygen> python -m signer.server &
uvicorn app.main:app --reload --port 8080

# 4. first admin and an enrolment code
python -m scripts.create_admin --username you --display-name "Your Name"
python -m scripts.issue_enrollment_code --username you

# 5. app and firmware
cd ../android && ./gradlew assembleDebug
cd ../firmware/esp32 && cp include/config.example.h include/config.h && pio run
```

Production deployment, with Quadlet units and a reverse proxy example:
[`docs/03-deployment.md`](docs/03-deployment.md)

## Project structure

```
evtimov-doors-control/
├── README.md
├── LICENSE                      MIT
├── .env.example                 every variable, empty, with an explanation
├── docs/
│   ├── 01-architecture.md       components, flows, decisions and why
│   ├── 02-threat-model.md       30 threats: control → failure → residual risk
│   ├── 03-deployment.md         rootless Podman, units, proxy, backups
│   └── 04-api.md                every endpoint with examples
├── backend/
│   ├── app/
│   │   ├── api/                 routers, dependencies
│   │   ├── core/                config, tokens, proximity, rate limiting, attestation
│   │   ├── db/                  pools and repositories
│   │   ├── models/              Pydantic schemas
│   │   ├── services/            auth, enrolment, unlock, audit
│   │   └── ws/                  controller connections
│   ├── admin/                   separate app, loopback only
│   ├── signer/                  isolated command signer
│   ├── db/
│   │   ├── apply.sh             idempotent, refuses to re-apply a changed file
│   │   ├── README.md            why raw SQL, how the append-only log works
│   │   └── migrations/          001-007, plain SQL
│   ├── deploy/                  Quadlet units, compose, nginx example
│   ├── tests/                   18 security + 12 role + 4 chain
│   └── scripts/                 create_admin, issue_enrollment_code
├── android/                     Kotlin, Compose, MVVM
├── firmware/esp32/              C++, PlatformIO, wiring diagram
└── .github/workflows/ci.yml
```

## Testing

```bash
cd backend
ACS_TEST_SUPERUSER_DSN="postgresql://postgres@127.0.0.1:5432/postgres" \
PYTHONPATH=. pytest -v
```

**34 tests against a real PostgreSQL 16 and a real signer process.** Nothing
about the database layer is mocked, because the database layer is where half
the controls live — a mock cannot refuse a `DELETE` that the grants refuse.
The signer runs as an actual subprocess on an actual Unix socket, and the fake
controller verifies signatures with the same library and the same canonical
bytes as the firmware.

| Group | What it covers |
|---|---|
| `test_security.py` (18) | expired and revoked tokens, refresh rotation, reuse detection, someone else's door, outside permitted hours, missing proximity, stale beacon, tampered command, signer limits, unlock rate limit, uniform login failures and timing, login lockout, blocked device, token storage, command expiry, silent controller, offline controller |
| `test_db_roles.py` (12) | `acs_app` cannot `UPDATE`/`DELETE`/`TRUNCATE` the audit log, can append and read, the owner is blocked by the trigger, partition truncation is blocked, `acs_audit` cannot read `users` or `tokens` or write operational tables, no `DELETE` anywhere, no DDL, no escalation, the hash chain cannot be forged |
| `test_audit_chain.py` (4) | a healthy chain verifies, a superuser edit is detected and named, a deleted row breaks the link, the head is anchorable |

```
$ pytest -q
..................................                                       [100%]
34 passed in 9.52s
```

CI runs the suite against the `postgres:16` service container, applies the
migrations twice to prove they are idempotent, builds the firmware and
assembles the app: [`.github/workflows/ci.yml`](.github/workflows/ci.yml)

## Threat model

Thirty threats across six attacker classes, each with what stops it, what
happens if that control fails, and what is left over:
[`docs/02-threat-model.md`](docs/02-threat-model.md)

The residual-risk column is the honest part. Four things this system does
**not** claim:

* Coercion is not addressed. Someone who can compel a fingerprint opens the
  door.
* The BLE relay attack (T-11) is mitigated, not solved.
* A database superuser can destroy data. They cannot silently alter it, which
  is a weaker and different guarantee.
* No network means no entry. That trade is deliberate, and the right override
  is a mechanical key in a lockbox — not a fallback in software.

## Roadmap

- [ ] **Round-trip-bounded proximity** — a connectable BLE characteristic with
      an RTT bound, or UWB ranging, to close T-11
- [ ] **External audit anchoring as a service** — periodic publication of
      `audit_chain_head()` to write-once storage, to close T-19
- [ ] **Signer key rotation without reflashing** — controllers accept a set of
      `key_id`s delivered over the authenticated socket
- [ ] **Offline grace with pre-signed, narrowly scoped commands** — one door,
      one user, minutes of validity, revocable on reconnect; the design work is
      deciding whether this is worth weakening the current guarantee at all
- [ ] **Multi-tenant sites** with per-site signers
- [ ] **Anomaly detection over the audit log** — unusual hours, unusual doors,
      impossible travel between controllers
- [ ] **Hardware watchdog on a second MCU**, so a wedged ESP32 is detected
      rather than merely reset

## License

MIT. Copyright (c) 2026 Boris Evtimov. See [LICENSE](LICENSE).
