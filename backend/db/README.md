# Database

PostgreSQL 16. Plain SQL migrations, numbered, immutable, applied by `apply.sh`.

```
backend/db/
├── apply.sh                    idempotent runner, refuses to re-apply a changed file
├── README.md                   this file
└── migrations/
    ├── 001_roles.sql           cluster roles, database level grants  (needs CREATEROLE)
    ├── 002_schema.sql          schema acs, enum types, schema_migrations
    ├── 003_core_tables.sql     users, devices, controllers, doors, permissions, tokens
    ├── 004_audit_log.sql       partitioned append-only table, partition management
    ├── 005_audit_chain.sql     hash chain trigger, deny guards, verify_audit_chain()
    ├── 006_grants.sql          least privilege, written out explicitly
    └── 007_seed_dev.sql        reference rows, applied only when ACS_SEED_DEV=1
```

## Running it

```bash
export ACS_DB_NAME=acs
export ACS_BOOTSTRAP_DSN="postgresql://postgres@127.0.0.1/acs"     # only 001 needs this
export ACS_MIGRATE_DB_DSN="postgresql://acs_migrate:***@127.0.0.1/acs"
export ACS_DB_MIGRATE_PASSWORD=... ACS_DB_APP_PASSWORD=... ACS_DB_AUDIT_PASSWORD=...

./apply.sh --dry-run      # show what would run
./apply.sh                # apply
```

`apply.sh` records every applied file with the SHA-256 of its contents in
`acs.schema_migrations`. If a file that has already been applied changes on
disk, the run stops. Corrections go into a new numbered file; a migration that
has run anywhere is never edited.

## Why plain SQL and not Alembic autogenerate

Alembic is a fine migration runner. `--autogenerate` is the part this schema
cannot use, because it compares SQLAlchemy model metadata against the live
database and emits the difference. Everything that makes this audit log
trustworthy is invisible to that comparison:

| Object here | What autogenerate does with it |
|---|---|
| `deny_mutation`, `deny_truncate`, `audit_hash_chain` triggers | Not modelled, not compared, silently absent from the generated script |
| `audit_hash_chain` being `SECURITY DEFINER` | Not modelled at all |
| `acs_app` / `acs_audit` / `acs_migrate` `GRANT`s | Roles and privileges are outside metadata; a regenerated schema comes back wide open |
| `audit_log PARTITION BY RANGE` + monthly partitions | Rendered as a plain table; partitions disappear |
| Partial unique index `permissions_active_unique ... WHERE is_active` | Frequently dropped or re-emitted as a full unique index, which changes behaviour |
| `CHECK (octet_length(public_key) = 32)` and friends | Inconsistently detected, often dropped on a later autogenerate pass |
| Enum types (`acs.actor_type`, ...) | Value additions and removals are not generated |

The failure mode is what makes it disqualifying: autogenerate does not error
on any of these. It produces a migration that applies cleanly and quietly
leaves the database without its triggers, without its grants, and without its
partitioning. A security control that can vanish without a failed build is not
a control.

So the schema is written where it is enforced, and the only thing the ORM
layer is trusted with is reading and writing rows. The backend uses asyncpg
directly against this schema; there is no model metadata that could drift from
it in the first place.

## The append-only audit log

Three independent layers, in order of how easy they are to defeat:

1. **Role grants.** `acs_app` and `acs_audit` hold `INSERT` and `SELECT` on
   `acs.audit_log`. No `UPDATE`, no `DELETE`, no `TRUNCATE`. An attacker with
   remote code execution in the API is holding a connection that cannot
   express the statement they want.
2. **Triggers.** `deny_mutation` (BEFORE UPDATE OR DELETE, on the partitioned
   table) and `deny_truncate` (BEFORE TRUNCATE, attached to every partition by
   `ensure_audit_partition`) raise `restrict_violation` regardless of who is
   asking — including `acs_migrate`, which owns the table. Grants can be
   changed by a superuser in one statement; this layer makes that not enough.
3. **Hash chain.** Every row stores the hash of its own canonical
   serialisation concatenated with the hash of the row before it. Both are
   computed by `acs.audit_hash_chain()`, a `SECURITY DEFINER` BEFORE INSERT
   trigger, from the row the database is about to store. Whatever the
   application sends in `prev_hash` and `row_hash` is overwritten. Inserts
   serialise on a transaction-scoped advisory lock so two concurrent writers
   cannot fork the chain.

`acs.verify_audit_chain(from_seq := 0)` walks the chain and returns
`(chain_ok, rows_checked, first_bad_seq, first_bad_reason)`. A superuser who
sets `session_replication_role = replica`, edits a row and sets it back gets
past layers 1 and 2 and is caught by layer 3:

```
 chain_ok | rows_checked | first_bad_seq |                first_bad_reason
----------+--------------+---------------+------------------------------------------------
 f        |            2 |             2 | row_hash does not match the row contents: ...
```

`backend/tests/test_audit_chain.py` performs exactly that attack and asserts
the row is named.

### What the chain does not catch

Deleting rows from the **end** of the chain leaves a shorter but internally
consistent chain. The chain proves order and content; it cannot prove that
nothing came after the last row it knows about. That is what
`acs.audit_chain_head()` is for: publish `(seq, row_hash)` periodically
somewhere the database administrator does not control — a second host, an
object store with write-once retention, a transparency log — and truncation of
the tail becomes an obvious mismatch instead of an invisible one. This is
listed as residual risk T-19 in `docs/02-threat-model.md`.

## Retention

Never `DELETE FROM audit_log`. Retention is a partition detach:

```sql
ALTER TABLE acs.audit_log DETACH PARTITION acs.audit_log_2025_01;
-- archive acs.audit_log_2025_01 somewhere, then drop it
```

Detaching does not touch any remaining row, so the chain over what is still
online stays verifiable from the first retained `seq` onward:
`SELECT * FROM acs.verify_audit_chain(p_from_seq => <first retained seq>);`

`acs.ensure_audit_partitions_ahead(2)` keeps the current and next month
present. Run it from cron; the insert path calls `ensure_audit_partition()`
lazily as well, so a missed cron run cannot lose an event.

## Roles

| Role | Used by | Holds |
|---|---|---|
| `acs_migrate` | `apply.sh` only | owner of schema `acs`, all DDL |
| `acs_app` | public API container | SELECT/INSERT/UPDATE on operational tables; SELECT/INSERT on `audit_log` |
| `acs_audit` | admin container | SELECT/INSERT on `audit_log` and nothing else — it cannot read `users` or `tokens` |

No role holds `DELETE` on any table. Removal is `is_active = false`,
`is_blocked = true` or `revoked_at = now()`.
