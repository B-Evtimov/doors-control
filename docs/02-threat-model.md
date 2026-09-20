# Threat model

Scope: an access control system where an Android phone is the only credential.
Assets, in the order they matter: **the doors themselves**, then **the audit
trail**, then **the identities** that can open doors.

Each row states a threat, what stops it, what happens if that control fails,
and what is left over. The residual column is the honest part — a threat model
whose residual risk is always "none" is a marketing document.

## Attacker classes

| | Who | Can do |
|---|---|---|
| **A1** | Opportunist near the door | pick up a dropped phone, watch, try the handle |
| **A2** | Remote attacker on the internet | reach the published API, scan, guess, replay |
| **A3** | Insider with database access | read and write the database directly, possibly as superuser |
| **A4** | Attacker with server code execution | own the API container |
| **A5** | Attacker with physical access to the controller | open the enclosure, cut wires, attach a programmer |
| **A6** | Attacker with malware on the phone | read app storage, call the API as the app |

---

## Credential and identity

| # | Threat | What stops it | If that fails | Residual risk |
|---|---|---|---|---|
| T-01 | **Phone stolen, unlocked** (A1) | Every unlock needs a Class 3 biometric; the Keystore key is generated with `setUserAuthenticationRequired(true)` and a 30 s window, so it refuses to sign without it | An unlocked phone in an attacker's hand opens doors the owner may open | A thief who coerces the owner's finger succeeds. No technical control fixes duress; the compensating control is the audit trail and fast revocation |
| T-02 | **Phone stolen, attacker adds their own fingerprint** (A1) | `setInvalidatedByBiometricEnrollment(true)` destroys the key when a biometric is enrolled | Key survives and works with the new finger | Device credential fallback is allowed for usability; a known lock-screen PIN still works until the device is revoked |
| T-03 | **Identity key extracted from the phone** (A6) | Key is generated in StrongBox or the TEE and is non-exportable; the app only ever holds a handle | Attacker can impersonate the device from anywhere | StrongBox has been defeated on specific devices. Attestation records which security level was used so a fleet can be audited |
| T-04 | **Access token stolen from app storage** (A6) | `EncryptedSharedPreferences` with a Keystore master key; backup and device transfer excluded app-wide; 15 minute lifetime | Attacker can call the API as the user for up to 15 minutes | Still needs a fresh beacon identifier, so the attack must happen at the door — T-10 |
| T-05 | **Refresh token stolen and used** (A6, A2) | Rotation with reuse detection: the first replay of a used token revokes the whole family | Attacker holds a self-renewing session | Detection is only triggered when the honest client refreshes. A thief who steals the token *and* the phone stays undetected until the owner uses the app |
| T-06 | **Token database dumped** (A3) | Only `SHA-256(pepper || token)` is stored; the pepper is in the process environment, not the database; input is 32 random bytes | Attacker has hashes | Nothing usable: no dictionary exists for 256-bit random values. If the pepper leaks *as well*, still nothing — the preimages are random |
| T-07 | **Password guessing** (A2) | Argon2id; per-user, per-IP and per-device counters in the database; progressive delay; hard lockout after 5 failures in the window | Attacker gets more attempts | Counters are durable in the database, so a container restart does not hand out a fresh budget. A large distributed source pool still slows the per-user counter down rather than stopping it |
| T-08 | **Username enumeration** (A2) | One error body and one status for every authentication failure, plus a fixed response-time budget and a dummy Argon2 verification on the missing-user path | Attacker learns which accounts exist | Tested by `test_login_failures_are_indistinguishable`. Traffic analysis of response *size* is identical; extreme load could still create a timing signal |
| T-09 | **Repackaged or instrumented app** (A6) | Play Integrity verdict at enrolment, bound by nonce to the same attestation challenge as the key | An attacker's build enrols | Play Integrity has been bypassed on rooted devices. Key attestation is the independent second statement; both must pass in `strict` mode |

## Proximity and the door itself

| # | Threat | What stops it | If that fails | Residual risk |
|---|---|---|---|---|
| T-10 | **Remote unlock with a stolen token** (A2, A6) | Unlock requires a beacon identifier from one of the last three 30 s slots, recomputed server-side from the shared key | Any valid token opens any permitted door from anywhere | This is the main reason the beacon exists. The phone's clock is not consulted, so it cannot be manipulated to widen the window |
| T-11 | **BLE relay attack** (A1) | Partially: the identifier is short-lived, and the attacker needs the phone to be unlocked and biometrically authenticated at that moment | An attacker with a radio at the door and a radio near the victim opens the door | **Not solved.** A plain advertisement cannot bound round-trip time. The fix is a connectable characteristic with an RTT bound, or UWB ranging. On the roadmap |
| T-12 | **Beacon identifier recorded and replayed later** (A1) | Identifiers rotate every 30 s; the server accepts at most three slots | A recording opens the door indefinitely | A recording is useful for at most 90 seconds, during which the attacker also needs a live token and a biometric |
| T-13 | **Beacon key extracted from a controller** (A5) | Physical security of the enclosure; tamper switch reports to the audit log | Attacker can generate valid identifiers and satisfy the proximity check remotely | Real. Proximity is defence in depth, not the authorisation decision — the attacker still needs a live token and a permission. Beacon keys are per-controller, so one board does not compromise the site |
| T-14 | **Forged unlock command sent to a controller** (A2, A4) | The controller verifies an Ed25519 signature over canonical bytes before it touches the relay; the key is in a process with no network | Any door opens on demand | The firmware rebuilds the signed bytes itself rather than re-serialising parsed JSON, so an unknown field fails verification rather than being ignored |
| T-15 | **Signed command captured and replayed** (A2, A5) | `expires_at` is checked against the controller's own NTP-synced clock, at most 30 s after issue; `command_id` is kept in a replay ring | A recorded command opens the door whenever the attacker chooses | Freshness is not part of the signature, by design. If the controller's clock is wrong, commands are refused rather than accepted — it fails closed |
| T-16 | **Command for door A replayed at door B** (A2) | `controller_code` is inside the signed payload and checked by the firmware | One door's command opens another | Refused even though the signature is valid |
| T-17 | **Physical attack on the controller** (A5) | Fail-secure strike (no current = locked); controller mounted on the secure side; tamper switch; no local unlock path in firmware | Attacker with the enclosure open can bridge the relay contacts by hand | Unavoidable. Anyone who can reach the relay terminals can open the door with a wire — that is a property of electric locks, not of this system. The tamper event is logged and the strike is rated for the door, not the controller |
| T-18 | **Firmware replaced over OTA** (A2) | Manifest signed with a key separate from the command signing key; signature covers version, size *and* hash; image hashed while streaming and checked before the boot switch; two OTA slots for rollback | Attacker ships firmware that opens on command | Signing the hash alone would allow a valid signature over a substituted image under a different version string — which is why all three are signed together. Setting `ACS_OTA_MANIFEST_URL` empty removes this path entirely |

## The audit trail

| # | Threat | What stops it | If that fails | Residual risk |
|---|---|---|---|---|
| T-19 | **Audit rows edited to hide an entry** (A3) | Three layers: role grants, `deny_mutation`/`deny_truncate` triggers, and an in-database hash chain; `verify_audit_chain()` names the first bad row | The record of what happened becomes unreliable | A superuser who disables triggers is still caught by the chain — proven in `test_audit_chain.py`. **Truncating the tail is not caught**: publish `audit_chain_head()` to an external witness to close this |
| T-20 | **Audit table dropped or truncated** (A3, A4) | `acs_app` and `acs_audit` hold no `TRUNCATE`; every partition carries a `deny_truncate` trigger; only `acs_migrate` can run DDL and no service uses it | Whole periods vanish | A superuser can still `DROP TABLE`. Off-host backups and the external head anchor are the answer; this is a backup problem, not a schema one |
| T-21 | **Application writes a false audit row** (A4) | `prev_hash` and `row_hash` are computed by the trigger from the row being stored; whatever the application sends is overwritten | A compromised API writes plausible lies | A compromised API *can* append true-looking rows about events that did not happen. What it cannot do is remove or alter rows about events that did. That asymmetry is the design goal |
| T-22 | **Audit log fills the disk** (A2 via request flooding) | Rate limiting caps event generation per user; monthly partitions make retention a detach | The database stops accepting writes and the system fails closed | Fails closed, which is correct but is an availability incident. Monitor partition size |

## Server and infrastructure

| # | Threat | What stops it | If that fails | Residual risk |
|---|---|---|---|---|
| T-23 | **Code execution in the API container** (A4) | Rootless Podman, read-only root filesystem, all capabilities dropped, `no-new-privileges`, `acs_app` holds no DELETE and no DDL, signing key is in another container with no network | Attacker opens doors at will while they are there | They can open doors, and every one of those unlocks is in the audit log, appended by them and unremovable by them. They cannot mint commands for later use |
| T-24 | **Signer compromised** (A4) | It parses one JSON object per line from one socket; that file is its whole attack surface; no network namespace; read-only root | Attacker mints unlock commands indefinitely | Unrecoverable without rotating the key and reflashing every controller. Hence the tiny surface. Key rotation is supported through `key_id` |
| T-25 | **Admin panel reached from the internet** (A2) | Separate app, separate container, separate database role, bound to `127.0.0.1`, no public hostname, no DNS record, CIDR allowlist middleware | An attacker can grant themselves a door and read the trail | Reachable only from the host or the private mesh. Someone with SSH or VPN access already has more direct routes |
| T-26 | **Database credentials leaked** (A3) | Three roles with distinct DSNs and least privilege; `acs_app` cannot delete anything or run DDL; `acs_audit` cannot read `users` or `tokens` | Attacker reads and writes what that role could | Worst case is `acs_app`: read everything operational, append audit rows, revoke nothing permanently. It still cannot erase the record of its own activity |
| T-27 | **TLS interception between phone and server** (A2) | Certificate pinning with backup pins on the intermediate; `network_security_config.xml` refuses user-added certificate authorities; cleartext disabled in every build | Tokens and requests are readable and forgeable | An attacker who can install a system-level certificate on the device already owns the device — T-03, T-06 |
| T-28 | **Denial of service against the API** (A2) | Rate limiting per user, device and IP; short statement timeouts; small request body limits at the proxy; the controller link is a long-lived socket that does not re-handshake | Doors cannot be opened | Fails closed. The system is explicit that it has no offline mode; the operational answer is a mechanical key for the site, not a software fallback |
| T-29 | **Denial of service against a controller's uplink** (A2, A5) | Watchdog, automatic reconnection, fail-closed | Doors stay locked while the link is down | Jamming the Wi-Fi is an easy attack and it results in a locked door, which is the correct failure — but it *is* a denial of service and no amount of cryptography changes that |
| T-30 | **Malicious or compromised administrator** (A3) | Every administrative action is an audit row: who granted what, to whom, when, in what window | An administrator grants themselves access | Not preventable — an administrator's job is granting access. It is made *visible*: the grant and the unlock that follows are both in a log the administrator cannot rewrite without breaking the chain |

---

## Things this model does not claim

* **Coercion is not addressed.** Someone who can compel a fingerprint opens
  the door. That is a physical-security and policy problem.
* **The BLE relay is open.** T-11 is mitigated, not solved.
* **A superuser on the database host can destroy data.** They cannot silently
  alter it, which is a different and weaker guarantee than "cannot destroy".
* **Availability is a real cost.** No network means no entry. That trade is
  deliberate and should be made consciously per site, with a mechanical
  override that is a key in a lockbox rather than a fallback in software.
* **Nothing here has been penetration tested.** This is a threat model, which
  is a statement of intent and a map of where to look — not evidence.
