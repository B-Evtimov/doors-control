# ESP32 door controller

ESP32-WROOM-32 (38 pin), Arduino framework, built with PlatformIO.

The controller is the least trusted part of the system on purpose. It does not
know who the user is, it holds no user data, it has no database connection and
it has no inbound network port. It receives one kind of message — "open door
X, signed" — verifies the signature itself, and pulses a relay for three
seconds.

## What it does

| | |
|---|---|
| Connection | outbound WSS to the backend, kept open with ping/pong |
| Identity | Ed25519 challenge-response at connect, private key compiled in |
| Commands | Ed25519 signature verified on-board before the relay is touched |
| Relay | fixed pulse, clamped to `ACS_RELAY_MAX_MS` (3 s) in firmware |
| Failure mode | every failure leaves the door locked |
| Proximity | BLE beacon with a 30 second rotating identifier |
| Updates | signed OTA with a separate key, hash checked before the boot switch |
| Watchdog | 15 s; a hang resets the board, which de-energises the relay |
| Status | one LED, six patterns |

## Wiring

![Wiring diagram](wiring.svg)

```
                 ESP32-WROOM-32 (38 pin)
                 ┌──────────────────────┐
                 │                      │
   5 V ──────────┤ 5V            GPIO26 ├────────► relay IN
   GND ──────────┤ GND           GPIO27 ├────────► reed switch ──┐
                 │               GPIO14 ├────────► tamper sw. ───┤
                 │                GPIO2 ├──► status LED          │
                 │                      │                       GND
                 └──────────────────────┘

   Relay module (opto-isolated, JD-VCC)
   ┌─────────────────────────────┐
   │ IN   ◄── GPIO26             │
   │ VCC  ◄── 5 V                │        12 V supply (strike only)
   │ GND  ◄── GND  (common)      │        ┌──────────┐
   │                             │        │  +    −  │
   │ COM ─────────────────────────────────┼──┘    │  │
   │ NO  ──► strike +            │        │       │  │
   │ NC  (unused)                │        └───────┼──┘
   └─────────────────────────────┘                │
              electric strike, fail-secure, 12 V  │
              ┌───────────────┐                   │
    strike + ─┤  coil   ⟂ 1N4007 flyback  ├────── strike −
              └───────────────┘
```

Five things that matter more than the pinout:

1. **Fail-secure strike, not fail-safe.** No current means locked. A fail-safe
   strike unlocks when the power goes out, which turns a tripped breaker into
   an open door.
2. **The strike current never touches the ESP32.** Only the relay contacts
   carry it, on a separate 12 V supply, with the grounds tied at one point.
3. **Flyback diode across the coil**, cathode to +12 V. Without it the
   collapsing field will eventually weld the relay contacts or reset the board.
4. **Relay `IN` is driven from GPIO26.** If your relay board energises on LOW,
   set `ACS_RELAY_ACTIVE_HIGH` to 0 — do not rewire around it, because the
   firmware drives the safe level before the pin becomes an output and that
   only works if the level is right.
5. **Mount the controller on the secure side of the door.** Everything below
   assumes an attacker who can reach the door cannot reach the board. The
   tamper switch is there because that assumption is sometimes wrong.

## Building

```bash
cd firmware/esp32
cp include/config.example.h include/config.h
# generate this controller's key material
python -m signer.keygen --controller          # from backend/
# paste the C arrays into include/config.h, register the public key and
# beacon key in acs.controllers
pio run -e esp32dev
pio run -e esp32dev -t upload
pio device monitor
```

`include/config.h` is in `.gitignore`. It contains the controller's private
key and must never be committed.

## The handshake, exactly

```
controller ──► server   TLS, certificate validated against the pinned CA
server     ──► controller {"type":"challenge","nonce":"<b64>","server_time":…}
controller ──► server   {"type":"auth","controller_code":"…",
                         "signature":"<b64>","firmware_version":"1.0.0"}
server     ──► controller {"type":"auth_ok","heartbeat":25,…}
```

The signature is Ed25519 over

```
"acs-controller-auth:v1\0" || controller_code || "\0" || nonce
```

The nonce is fresh per connection, so a recorded handshake replays into
nothing. The server proves nothing to the controller at this layer because TLS
already did: the certificate is checked against a CA compiled into the
firmware before any of this is sent.

## The command, exactly

```json
{
  "type": "command",
  "payload": {
    "cmd": "unlock",
    "command_id": "…uuid…",
    "controller_code": "ctrl-01",
    "door_code": "door-01",
    "duration_ms": 3000,
    "expires_at": 1767225610,
    "issued_at": 1767225600,
    "nonce": "…",
    "relay_channel": 1
  },
  "signature": "<base64 Ed25519>",
  "key_id": "signer-1",
  "alg": "ed25519"
}
```

The signature covers

```
"acs-command:v1\0" + json.dumps(payload, sort_keys=True, separators=(",", ":"))
```

The firmware rebuilds those bytes field by field in sorted key order rather
than re-serialising what its JSON parser produced, because a parser is allowed
to normalise things a signature is not. A payload carrying a field this
firmware does not know about therefore fails verification instead of being
accepted with the unknown part quietly ignored.

Before the relay moves, the firmware checks, in this order:

1. the payload parses and `cmd` is `unlock`
2. `controller_code` is this controller — a correctly signed command for the
   door down the corridor is still refused here
3. the Ed25519 signature verifies against `ACS_SIGNER_PUBLIC_KEY`
4. the clock is synchronised at all
5. `expires_at` has not passed, allowing `ACS_MAX_CLOCK_SKEW_S` of slack
6. `issued_at` is not in the future
7. `command_id` is not in the ring of recently honoured commands

Then, and only then, `relay.pulse(duration_ms)` — clamped to
`ACS_RELAY_MAX_MS` whatever the command asked for.

Note that freshness is deliberately *not* part of the signature. A signature
is valid forever; that is what signatures are. Expiry is checked separately,
against the controller's own clock, which is why NTP is a security control on
this board and not a convenience.

## The beacon

```
id(slot) = HMAC-SHA256(beacon_key, "acs-beacon:v1" || slot)[:16]
slot     = floor(unix_seconds / 30)
```

Advertised as non-connectable manufacturer data under `0xFFFF` (the "no
company assigned" identifier, which is the correct choice for a private
protocol). The board accepts no BLE connections.

If the clock is not synchronised the beacon is not advertised at all. An
identifier from the wrong slot would be rejected by the server anyway, and a
silent beacon is a clearer symptom than a useless one.

## What the LED says

| Pattern | Meaning |
|---|---|
| Fast blink, 5 Hz | joining Wi-Fi |
| Slow blink, 1 Hz | Wi-Fi up, connecting or authenticating to the server |
| Solid on | connected and authenticated |
| Three short pulses | a command was refused |
| Solid on for 3 s | the relay is energised |
| Off | no power |

## Signed updates

```bash
pio run -e esp32dev
python scripts/sign_firmware.py \
    --image .pio/build/esp32dev/firmware.bin \
    --version 1.1.0 \
    --url https://updates.example.invalid/firmware-1.1.0.bin \
    --key-file ~/.acs/ota-private.key > manifest.json
```

The OTA key is separate from the command signing key, so stealing one does not
give the other. The manifest signature covers the version, the size and the
hash together — signing only the hash would let an attacker keep a valid
signature while serving a different image under a different version string.

The image is streamed into the inactive OTA slot and hashed as it arrives; the
hash is compared before the boot partition is switched. Two slots are
configured in `partitions.csv`, so a bad image rolls back instead of bricking
a door.

Leave `ACS_OTA_MANIFEST_URL` empty to compile the update path out of the
decision tree entirely. A door that never checks for updates cannot be
attacked through its update path.

## What this firmware deliberately does not have

* **No local unlock.** No button, no keypad header, no serial command that
  opens the door. The only path to the relay goes through a verified
  signature.
* **No inbound port.** It dials out and it never listens.
* **No stored user data.** It does not know who opened the door, and cannot
  leak what it does not hold.
* **No fallback mode.** If the server is unreachable the door stays locked.
  That is a real operational cost and it is the correct trade for a lock.
