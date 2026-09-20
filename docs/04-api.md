# API

Base URL: `https://api.example.invalid`

Every request and response body is a Pydantic model; unknown fields are
rejected rather than ignored. Every error has the same shape:

```json
{ "error": "invalid_credentials" }
```

Handled errors raised through FastAPI's exception path nest it once:

```json
{ "detail": { "error": "invalid_credentials" } }
```

## Authentication

`Authorization: Bearer <access token>`

The token is 32 random bytes, URL-safe base64, with no structure. There is
nothing in it to decode. It is valid for 15 minutes and stops working the
instant its row is revoked — see [why not JWT](01-architecture.md#opaque-tokens-not-jwts).

## Error codes

| Code | Status | Meaning |
|---|---|---|
| `invalid_credentials` | 401 | Any authentication failure at all. Deliberately undifferentiated |
| `denied` | 403 | No grant, outside the time window, unknown door, or a blocked controller |
| `not_present` | 403 | No fresh proximity proof |
| `controller_offline` | 403 | The door's controller is not connected |
| `failed` | 403 | The controller refused or did not acknowledge. **Nothing was opened** |
| `rate_limited` | 429 | With a `Retry-After` header |
| `not_found` | 404 | |
| `conflict` | 409 | Device already enrolled |

`denied` is coarse on purpose. "You have no grant for this door" and "you are
outside your permitted hours" are both useful to an attacker mapping a
building. Which one it was is in the audit log.

---

## `POST /api/v1/auth/enroll/challenge`

Start enrolment. Returns the attestation challenge the phone must generate its
key over.

```json
{ "enrollment_code": "8mJk...-code-from-your-administrator" }
```

```json
{ "challenge": "base64-32-bytes", "expires_in": 300 }
```

This answers the same way whether the code is real. A challenge is worthless
without a matching unused code, which is checked at the next step.

## `POST /api/v1/auth/enroll`

```json
{
  "enrollment_code": "8mJk...",
  "label": "Pixel 8",
  "device_public_key": "base64-32-byte-ed25519-key",
  "attestation_chain": ["-----BEGIN CERTIFICATE-----\n...", "..."],
  "play_integrity_token": "...",
  "challenge": "base64-the-challenge-from-above",
  "platform": "android",
  "app_version": "1.0.0"
}
```

```json
{
  "device_id": "0f6c...",
  "attestation_status": "verified",
  "access_token": "...",
  "refresh_token": "...",
  "expires_in": 900
}
```

The server checks, in order: the challenge matches the one it issued; the
enrolment code is unused and unexpired (claimed atomically); the certificate
chain verifies and says the key is in secure hardware on a device with a
locked bootloader and user authentication required; the Play Integrity verdict
recognises the app.

With `ACS_ATTESTATION_MODE=strict`, a failure at any of those is
`401 invalid_credentials` and no device row is created.

## `POST /api/v1/auth/login`

```json
{ "username": "boris", "password": "...", "device_id": "0f6c..." }
```

```json
{ "access_token": "...", "refresh_token": "...", "token_type": "Bearer", "expires_in": 900 }
```

Every failure — unknown user, wrong password, disabled account, device not
bound to this user, blocked device, unattested device — returns the same body,
the same status and, within measurement noise, the same elapsed time.

## `POST /api/v1/auth/refresh`

```json
{ "refresh_token": "..." }
```

Returns a new pair. **The old refresh token stops working immediately.**

Presenting a refresh token that has already been used revokes every token in
its family, including any pair a thief has just obtained, and returns 401. A
client must therefore never refresh concurrently: two in-flight refreshes
present the same rotated token twice and the server cannot tell that apart
from theft.

## `POST /api/v1/auth/logout`

Requires a bearer token.

```json
{ "refresh_token": "...", "all_devices": false }
```

`204`. `all_devices: true` revokes every live token for this device.

---

## `GET /api/v1/doors`

Requires a bearer token. Returns the doors this user currently holds a live
grant for, with the time window already evaluated in the permission's own time
zone.

```json
{
  "doors": [
    {
      "id": "3c1e...",
      "code": "door-01",
      "name": "Front door",
      "location": "Ground floor",
      "unlock_seconds": 3,
      "controller_online": true,
      "window_start": "08:00:00",
      "window_end": "18:00:00",
      "weekday_mask": 31,
      "time_zone": "Europe/Sofia"
    }
  ],
  "server_time": "2026-09-20T14:31:02.118Z"
}
```

`weekday_mask` is a bitmask with bit 0 = Monday, matching ISO-8601. `31` is
Monday to Friday.

The unlock endpoint re-checks everything this endpoint reports. The list is
what the phone may *try*, not a permission.

## `POST /api/v1/doors/{door_id}/unlock`

```json
{ "proximity_beacon_id": "0hGm...", "client_request_id": "uuid" }
```

```json
{
  "result": "opened",
  "door_id": "3c1e...",
  "command_id": "9b21...",
  "opened_for_ms": 3000,
  "proximity_age_seconds": 12
}
```

`200` means the controller acknowledged that it energised the relay. Anything
else means the door did not open.

The checks, in order — cheap ones first so that the signer is never used as an
oracle:

1. door exists, is active, has a controller → `denied`
2. live grant for this user and door, inside its window → `denied`
3. controller not blocked → `denied`
4. the beacon identifier matches one of the last three 30-second slots → `not_present`
5. unlock attempts in the last minute under the limit → `429`
6. the controller is connected → `controller_offline`
7. the signer signs the command
8. the controller verifies, opens, and acknowledges → otherwise `failed`

Every branch writes an audit row with the real reason before it returns.

## `GET /api/v1/me/access-history?limit=50`

```json
{
  "records": [
    {
      "seq": 41233,
      "occurred_at": "2026-09-20T14:31:02.118Z",
      "event_type": "door.unlock_confirmed",
      "outcome": "success",
      "door_id": "3c1e...",
      "detail": { "command_id": "9b21..." }
    }
  ]
}
```

Filtered to this user server-side. There is no parameter that widens it.

---

## `GET /health`

`{"status": "ok"}`. Cheap, and says nothing useful to a stranger.

## `GET /health/ready`

Not for the internet.

```json
{
  "status": "ok",
  "version": "1.0.0",
  "database": true,
  "signer": true,
  "controllers_online": 2,
  "audit_chain_ok": true
}
```

---

## Admin API

Separate application, `127.0.0.1:8081`, no public hostname. Requires a bearer
token belonging to a user with `is_admin`. A non-admin gets
`401 invalid_credentials`, the same as anyone else — nothing here confirms the
endpoint exists.

### `GET /admin/v1/audit?limit=100&before_seq=&event_type=`

```json
[
  {
    "seq": 41233,
    "occurred_at": "2026-09-20T14:31:02.118Z",
    "event_type": "door.unlock_granted",
    "outcome": "success",
    "actor_type": "user",
    "actor_id": "…",
    "device_id": "…",
    "door_id": "…",
    "controller_id": "…",
    "client_ip": "203.0.113.9",
    "detail": { "command_id": "…", "signer_key_id": "signer-1" },
    "row_hash": "9f12…"
  }
]
```

### `GET /admin/v1/audit/verify?from_seq=0`

```json
{
  "chain_ok": true,
  "rows_checked": 41233,
  "first_bad_seq": null,
  "first_bad_reason": null,
  "head_seq": 41233,
  "head_hash": "9f12…"
}
```

Monitor this. `chain_ok: false` is the only signal that someone has been in
the database. Record `head_seq` and `head_hash` off-host — see T-19.

### `GET /admin/v1/controllers`

```json
[
  {
    "id": "…", "code": "ctrl-01", "name": "Front door",
    "firmware_version": "1.0.0", "is_blocked": false,
    "last_seen_at": "2026-09-20T14:30:58Z", "online": true
  }
]
```

### `POST /admin/v1/controllers`

```json
{
  "code": "ctrl-01",
  "name": "Front door",
  "public_key": "base64-32-bytes",
  "beacon_key": "base64-32-bytes"
}
```

`201 {"controller_id": "…"}`

### `POST /admin/v1/controllers/{id}/block?reason=...`

`204`. The controller's doors immediately report as unavailable.

### `POST /admin/v1/doors`

```json
{
  "code": "door-01", "name": "Front door", "location": "Ground floor",
  "controller_id": "…", "relay_channel": 1, "unlock_seconds": 3
}
```

### `POST /admin/v1/permissions`

```json
{
  "user_id": "…",
  "door_id": "…",
  "weekday_mask": 31,
  "start_time": "08:00:00",
  "end_time": "18:00:00",
  "time_zone": "Europe/Sofia",
  "valid_until": "2027-01-01T00:00:00Z"
}
```

`201 {"permission_id": "…"}`. A user holds at most one live grant per door;
posting again updates it. The previous row stays for the record with
`is_active = false`, and the grant itself is an audit row naming the
administrator who made it.

---

## Controller WebSocket

`wss://api.example.invalid/ws/controller` — outbound from the controller only.

```
server → { "type": "challenge", "nonce": "<b64>", "server_time": 1767225600 }
client → { "type": "auth", "controller_code": "ctrl-01",
           "signature": "<b64>", "firmware_version": "1.0.0" }
server → { "type": "auth_ok", "heartbeat": 25, "signer_key_id": "signer-1" }

server → { "type": "ping" }        client → { "type": "pong" }

server → { "type": "command", "payload": {...}, "signature": "<b64>",
           "key_id": "signer-1", "alg": "ed25519" }
client → { "type": "ack", "command_id": "…", "result": "opened",
           "detail": "ok", "relay_ms": 3000, "uptime_ms": 918273 }

client → { "type": "event", "event": "tamper", "outcome": "failure",
           "detail": { "state": "open" } }
```

The auth signature is Ed25519 over
`"acs-controller-auth:v1\0" || controller_code || "\0" || nonce`.

The command signature is Ed25519 over
`"acs-command:v1\0" || json.dumps(payload, sort_keys=True, separators=(",", ":"))`.

Wire-level details and the exact field order are in
[`firmware/esp32/README.md`](../firmware/esp32/README.md).
