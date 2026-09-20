# Deployment

Rootless Podman on a Linux host. Every host name, domain and path below is an
example; nothing real is committed to this repository.

## Shape

```
                    internet
                        │
                        ▼
           ┌─────────────────────────┐
           │ reverse proxy / tunnel  │   TLS terminates here
           │  api.example.invalid    │
           └────────────┬────────────┘
                        │ 127.0.0.1:8080
   ┌────────────────────┴───────────────────────────────┐
   │  unprivileged user `acs`, rootless Podman          │
   │                                                    │
   │  acs-api ──unix socket──► acs-signer               │
   │     │                     (no network namespace)   │
   │     ▼                                              │
   │  PostgreSQL 16 ◄──── acs-admin (127.0.0.1:8081)    │
   └────────────────────────────────────────────────────┘

   the admin app has no public hostname and no DNS record
```

## Why the admin application is not published

It can grant a person access to a door, revoke a device and read the entire
audit trail. The phone app can do none of those things. They share a database
and nothing else.

Publishing them together would put permission-minting code paths inside the
process that faces the internet, so every bug in the phone-facing half becomes
a potential route into the operator half. Keeping them apart means an attacker
who fully owns the public API still cannot grant themselves a permanent
permission — they can open doors while they are there, and every one of those
unlocks is in a log they cannot edit.

Binding it to `127.0.0.1` with no DNS record means it is not merely protected
from the internet; it is not addressable from it. There is no hostname to
resolve, no certificate to enumerate, nothing in certificate transparency logs
to find. Reaching it requires a shell on the host or a private mesh address,
and anyone with either already has more direct options.

`ACS_ADMIN_ALLOWED_CIDRS` is the belt to that braces: even reached over
loopback, the middleware checks the peer address.

## Host preparation

```bash
# One unprivileged user, owning nothing else on the machine.
sudo useradd --create-home --shell /bin/bash acs
sudo loginctl enable-linger acs        # so its units run without a login

sudo apt-get install -y podman uidmap passt
```

`uidmap` and `passt` are what make rootless networking work; without them
`podman` runs but publishing a port fails in ways that are hard to read.

Verify that rootless is actually available before going further:

```bash
sudo -u acs podman info --format '{{.Host.Security.Rootless}}'   # true
grep acs /etc/subuid /etc/subgid                                  # both present
```

## Database

Run PostgreSQL wherever you like — container or host package. It must not be
reachable from the internet; in the compose file it sits on an `internal`
network with no published port.

```bash
cd backend/db

export ACS_DB_NAME=acs
export ACS_BOOTSTRAP_DSN="postgresql://postgres@127.0.0.1/acs"
export ACS_MIGRATE_DB_DSN="postgresql://acs_migrate:***@127.0.0.1/acs"
export ACS_DB_MIGRATE_PASSWORD=...   # generate these, do not type them
export ACS_DB_APP_PASSWORD=...
export ACS_DB_AUDIT_PASSWORD=...

./apply.sh --dry-run
./apply.sh
```

`apply.sh` prints the applied migrations and the audit chain status when it
finishes. The chain should verify with zero rows on a fresh database.

Keep the current and next month's audit partitions alive:

```cron
17 3 * * * psql "$ACS_MIGRATE_DB_DSN" -c "SELECT acs.ensure_audit_partitions_ahead(2)"
```

The insert path also creates partitions lazily, so a missed cron run cannot
lose an event — the cron job exists to keep the latency of the first insert of
the month off the unlock path.

## Keys

```bash
cd backend

python -m signer.keygen                # signer keypair
python -m signer.keygen --controller   # one per door controller

# token pepper
python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
```

The signer's private key goes into a systemd credential read only by the
signer unit. It does not go into `api.env`, it does not go into the compose
file, and it never touches the repository.

Controller private keys go into that controller's `firmware/esp32/include/config.h`
on the machine that flashes the board, and nowhere else. The matching public
key and beacon key are registered through the admin API.

## Building and running

```bash
cd backend
podman build -t acs-api    -f Containerfile .
podman build -t acs-signer -f Containerfile.signer .
podman build -t acs-admin  -f Containerfile.admin .
```

### Quadlet units

Copy the unit files into the service user's Quadlet directory:

```bash
install -d ~/.config/containers/systemd
cp deploy/acs-*.container deploy/acs-*.network deploy/acs-*.volume \
   ~/.config/containers/systemd/

systemctl --user daemon-reload
systemctl --user start acs-signer acs-api acs-admin
systemctl --user status acs-api
```

The units are in [`backend/deploy/`](../backend/deploy/). The important lines,
and why:

| Line | Why |
|---|---|
| `Network=none` on the signer | it cannot reach the database, the internet, or any other container — only its socket |
| `ReadOnly=true` | nothing writes to the image filesystem; a dropped payload has nowhere to land |
| `DropCapability=ALL` | none of these processes needs a capability |
| `NoNewPrivileges=true` | no setuid path out of the container |
| `PublishPort=127.0.0.1:8080:8080` | the proxy faces the internet; this port does not |
| `Secret=acs-signer-key,type=env` | the signing key is a systemd credential, not a line in an env file |
| `Internal=true` on the network | containers can reach each other and nothing else |

Store the signer key as a Podman secret:

```bash
printf '%s' "$ACS_SIGNER_PRIVATE_KEY" | podman secret create acs-signer-key -
```

### Environment files

`~/.config/acs/api.env` and `~/.config/acs/admin.env`, mode `0600`, owned by
`acs`. Use [`.env.example`](../.env.example) as the checklist — every variable
there is documented with what it is for.

```bash
chmod 700 ~/.config/acs
chmod 600 ~/.config/acs/*.env
```

## Reverse proxy

A full example is in [`backend/deploy/nginx.example.conf`](../backend/deploy/nginx.example.conf).
Four things matter more than the rest:

1. **Only `/api/`, `/ws/controller` and `/health` are proxied.** Everything
   else returns 404. There is no hint that an admin application exists.
2. **`/ws/controller` needs long timeouts.** The controller link is a
   long-lived socket; the application's own heartbeat decides when a
   controller is gone, not the proxy's read timeout.
3. **`X-Forwarded-For` is only honoured from configured proxies.** Set
   `ACS_TRUSTED_PROXIES` to the proxy's address. Otherwise the header is a
   value the client chose, and trusting it would let anyone reset their own
   rate limit by changing one string.
4. **Small body limits.** No endpoint in this API needs more than a few
   kilobytes.

If you use a tunnel (Cloudflare Tunnel, Tailscale Funnel or similar) instead
of a public port, the same rules apply — publish only those three paths, and
give the tunnel its own credentials rather than reusing an account-wide one.

## Verifying the deployment

```bash
# liveness
curl -fsS https://api.example.invalid/health

# readiness, from the host: database, signer, audit chain, controllers online
curl -fsS http://127.0.0.1:8080/health/ready | jq

# the audit chain, from the admin app
curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
     http://127.0.0.1:8081/admin/v1/audit/verify | jq
```

`audit/verify` should return `chain_ok: true`. Wire it into whatever monitors
this host and alert on `false` — it is the only signal that someone has been
in the database.

Record the head hash somewhere the database administrator does not control:

```bash
psql "$ACS_AUDIT_DB_DSN" -tAc \
  "SELECT seq || ' ' || encode(row_hash,'hex') FROM acs.audit_chain_head()" \
  | tee -a /elsewhere/acs-audit-anchor.log
```

Without this, deleting the last N rows is undetectable. With it, it is
obvious. See T-19.

## Backups

```bash
pg_dump --format=custom "$ACS_MIGRATE_DB_DSN" > acs-$(date +%F).dump
```

Three properties a backup of this system needs:

* **Encrypted before it leaves the host.** The dump contains password hashes,
  device public keys and the whole audit trail. `age` or `gpg` with a key the
  backup destination does not hold.
* **Write-once, or at least append-only, at the destination.** A backup the
  attacker can delete is not a backup. If the upload credential holds delete
  rights, ransomware has delete rights.
* **Restore-tested.** An untested backup is a hypothesis.

Note that a restored dump has a verifiable chain: `verify_audit_chain()` works
on the restored database exactly as it did on the original, which means a
backup is also evidence.

## First administrator

```bash
podman exec -it acs-api python -m scripts.create_admin \
    --username boris --display-name "Boris Evtimov"
```

The password is prompted for, never passed as an argument — arguments are
visible in `ps`.

## Enrolling a phone

```bash
podman exec -it acs-api python -m scripts.issue_enrollment_code \
    --username boris --ttl 900
```

The code is printed once; only its SHA-256 is stored. Give it to the person
out of band, and they have fifteen minutes to enrol. If it is lost, issue
another one — there is nothing to recover.

## Adding a controller

1. `python -m signer.keygen --controller`
2. Paste the C arrays into that board's `firmware/esp32/include/config.h`
3. Register the public key and beacon key:

```bash
curl -fsS -X POST http://127.0.0.1:8081/admin/v1/controllers \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"code":"ctrl-01","name":"Front door","public_key":"<b64>","beacon_key":"<b64>"}'
```

4. Flash the board. It dials out and appears in
   `GET /admin/v1/controllers` as online within a few seconds.

## Operational checklist

- [ ] `/health/ready` monitored, alerting on `degraded`
- [ ] `audit/verify` monitored, alerting on `chain_ok: false`
- [ ] audit chain head anchored off-host, daily
- [ ] backups encrypted, write-once, restore tested
- [ ] `ACS_TRUSTED_PROXIES` matches the actual proxy
- [ ] `ACS_ATTESTATION_MODE=strict` in production
- [ ] admin application has no DNS record — check, do not assume
- [ ] a mechanical override exists for the site, and it is a key in a lockbox
      rather than a fallback in software
