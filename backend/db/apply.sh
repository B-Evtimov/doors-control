#!/usr/bin/env bash
# ============================================================================
#  apply.sh - apply the numbered SQL migrations, in order, exactly once.
#
#  Usage:
#     ACS_DB_NAME=acs \
#     ACS_BOOTSTRAP_DSN="postgresql://postgres@localhost/acs" \
#     ACS_MIGRATE_DB_DSN="postgresql://acs_migrate:...@localhost/acs" \
#     ACS_DB_MIGRATE_PASSWORD=... ACS_DB_APP_PASSWORD=... ACS_DB_AUDIT_PASSWORD=... \
#     ./apply.sh [--dry-run] [--seed-dev]
#
#  001_roles.sql is the only file that needs a role with CREATEROLE, so it is
#  applied with ACS_BOOTSTRAP_DSN. Everything after it runs as acs_migrate.
#
#  Already applied files are skipped. If a file that was already applied has
#  changed on disk the script stops: migrations are immutable, corrections go
#  into a new numbered file.
# ============================================================================
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIGRATIONS="${HERE}/migrations"

DRY_RUN=0
SEED_DEV="${ACS_SEED_DEV:-0}"

for arg in "$@"; do
    case "$arg" in
        --dry-run)  DRY_RUN=1 ;;
        --seed-dev) SEED_DEV=1 ;;
        -h|--help)  sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

require() {
    local name="$1"
    if [[ -z "${!name:-}" ]]; then
        echo "error: ${name} is not set. See .env.example." >&2
        exit 2
    fi
}

require ACS_DB_NAME
require ACS_MIGRATE_DB_DSN
require ACS_DB_MIGRATE_PASSWORD
require ACS_DB_APP_PASSWORD
require ACS_DB_AUDIT_PASSWORD

BOOTSTRAP_DSN="${ACS_BOOTSTRAP_DSN:-$ACS_MIGRATE_DB_DSN}"

psql_run() {
    local dsn="$1" file="$2"
    psql "$dsn" \
        --quiet --no-psqlrc --single-transaction \
        --set ON_ERROR_STOP=1 \
        --set "dbname=${ACS_DB_NAME}" \
        --set "migrate_password=${ACS_DB_MIGRATE_PASSWORD}" \
        --set "app_password=${ACS_DB_APP_PASSWORD}" \
        --set "audit_password=${ACS_DB_AUDIT_PASSWORD}" \
        --file "$file"
}

psql_value() {
    psql "$ACS_MIGRATE_DB_DSN" --quiet --no-psqlrc --tuples-only --no-align \
        --set ON_ERROR_STOP=1 --command "$1" 2>/dev/null || true
}

checksum_of() { sha256sum "$1" | cut -d' ' -f1; }

migrations_table_exists() {
    [[ "$(psql_value "SELECT to_regclass('acs.schema_migrations') IS NOT NULL")" == "t" ]]
}

declare -a PENDING=()

record_pending() {
    migrations_table_exists || return 0
    local entry version sum
    for entry in "${PENDING[@]:-}"; do
        [[ -z "$entry" ]] && continue
        version="${entry%%:*}"
        sum="${entry#*:}"
        psql "$ACS_MIGRATE_DB_DSN" --quiet --no-psqlrc --set ON_ERROR_STOP=1 \
            --command "INSERT INTO acs.schema_migrations (version, checksum)
                       VALUES ('${version}', '${sum}')
                       ON CONFLICT (version) DO NOTHING" >/dev/null
    done
    PENDING=()
}

applied_checksum() {
    migrations_table_exists || { echo ""; return 0; }
    psql_value "SELECT checksum FROM acs.schema_migrations WHERE version = '$1'"
}

echo "==> database : ${ACS_DB_NAME}"
echo "==> directory: ${MIGRATIONS}"
[[ $DRY_RUN -eq 1 ]] && echo "==> dry run, nothing will be applied"

shopt -s nullglob
for file in "${MIGRATIONS}"/[0-9][0-9][0-9]_*.sql; do
    version="$(basename "$file" .sql)"

    if [[ "$version" == *_seed_dev && "$SEED_DEV" != "1" ]]; then
        echo "--  ${version}  skipped (ACS_SEED_DEV is not 1)"
        continue
    fi

    sum="$(checksum_of "$file")"
    prev="$(applied_checksum "$version")"

    if [[ -n "$prev" ]]; then
        if [[ "$prev" != "$sum" ]]; then
            echo >&2
            echo "error: ${version} was already applied but the file has changed." >&2
            echo "       applied checksum: ${prev}" >&2
            echo "       file checksum   : ${sum}" >&2
            echo "       Migrations are immutable. Add a new numbered file." >&2
            exit 1
        fi
        echo "--  ${version}  already applied"
        continue
    fi

    if [[ $DRY_RUN -eq 1 ]]; then
        echo "++  ${version}  would apply"
        continue
    fi

    echo "++  ${version}  applying"
    if [[ "$version" == 001_* ]]; then
        psql_run "$BOOTSTRAP_DSN" "$file"
    else
        psql_run "$ACS_MIGRATE_DB_DSN" "$file"
    fi

    PENDING+=("${version}:${sum}")
    record_pending
done

record_pending

if [[ $DRY_RUN -eq 0 ]]; then
    echo
    echo "==> applied migrations:"
    psql "$ACS_MIGRATE_DB_DSN" --quiet --no-psqlrc --set ON_ERROR_STOP=1 \
        --command "SELECT version, applied_at, applied_by FROM acs.schema_migrations ORDER BY version"
    echo "==> audit chain:"
    psql "$ACS_MIGRATE_DB_DSN" --quiet --no-psqlrc --set ON_ERROR_STOP=1 \
        --command "SELECT * FROM acs.verify_audit_chain()"
fi
