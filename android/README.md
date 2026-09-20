# Android app

Kotlin, Jetpack Compose, MVVM. `minSdk 29`, because hardware key attestation
and StrongBox are the reason this app can claim anything about where its key
lives, and below 29 it cannot.

```
app/src/main/java/com/evtimov/doors/
├── MainActivity.kt            FragmentActivity - BiometricPrompt needs one
├── DoorsApplication.kt
├── di/ServiceLocator.kt       manual wiring; the graph is small enough
├── data/
│   ├── api/                   Retrofit interface, DTOs, OkHttp with pinning
│   ├── ble/BeaconScanner.kt   hears the door's rotating identifier
│   ├── crypto/
│   │   ├── KeystoreManager.kt hardware-backed identity key + attestation
│   │   └── BiometricGate.kt   the prompt that makes the key usable
│   ├── local/                 EncryptedSharedPreferences, DataStore
│   ├── DoorsRepository.kt
│   └── PlayIntegrityProvider.kt
├── domain/Models.kt
└── ui/
    ├── AppNavigation.kt
    ├── components/
    ├── screens/               enrolment, doors, history, settings
    └── theme/
```

## Screens

| Screen | What it does |
|---|---|
| Enrolment | one-time code → attestation challenge → key generation → enrol |
| Doors | the doors this user may open, with controller and proximity state shown separately |
| Unlock | biometric prompt, then the request, then an honest result |
| My access | this user's own rows from the audit log, fetched live |
| Settings | sign out, remove this phone, what this device is |

## The security relevant parts

**The identity key never leaves the phone.** It is generated inside the
Android Keystore with `setIsStrongBoxBacked(true)` where the hardware has a
secure element, falling back to the TEE otherwise. The app works with a
handle; the private bytes are never in this process's memory, so dumping the
app's memory or its data directory yields nothing that can be used elsewhere.

**Biometric authentication is a gate, not a dialog.** The key is generated
with `setUserAuthenticationRequired(true)` and a 30 second validity window,
so the Keystore refuses to sign until the user has authenticated. Someone
holding an unlocked phone without the owner's finger or face has a key that
does not work. `setInvalidatedByBiometricEnrollment(true)` means adding a new
fingerprint destroys the key rather than granting its use to a new finger.

**Attestation binds the key to a server-issued challenge.** The order matters:
ask for the challenge, then generate the key over it, then send the chain.
Generating first and asking afterwards would produce a chain that replays onto
any number of enrolments.

**Certificate pinning with backup pins.** Pins are on the intermediate
certificate, so renewal does not require an app release; a backup pin is
always shipped, because without one, losing a key bricks every installed copy.
`network_security_config.xml` additionally refuses user-added certificate
authorities, so an installed proxy certificate does not quietly become a man
in the middle.

**Tokens are in `EncryptedSharedPreferences`** with a Keystore-backed master
key, and backup is disabled app-wide so a token cannot ride a cloud restore
onto a different phone. Settings that are not credentials live in DataStore,
unencrypted, because pretending otherwise would be noise.

**Refresh is serialised process-wide.** The server rotates refresh tokens and
revokes the whole family when it sees one reused. Two concurrent refreshes in
the app would present the same rotated token twice, and the server would -
correctly - treat that as theft. The lock in `ApiClient` is what stops the app
triggering the server's own theft detection against itself.

**The proximity identifier is read inside the repository**, from the scanner,
at the moment of the request. There is no path through the app that sends a
value the scanner did not actually hear inside the freshness window.

**BLE scanning runs only while the door list is in front.** Declared with
`neverForLocation`, because this app does not want location and does not
derive it.

## Offline behaviour

The app is honest rather than optimistic. With no connection it says so and
disables the unlock button. Nothing is cached, nothing is queued for later,
and no door opens without a fresh signature from the server. An access control
app that looks like it worked when it did not is worse than one that plainly
says it could not.

The door list shows two conditions separately — "controller offline" and
"move closer" — because they have different remedies. One means walk a few
metres; the other means call someone.

## Building

```bash
cd android
./gradlew assembleDebug
```

Before a release build, replace the placeholders in `app/build.gradle.kts`:

| Field | What to put in it |
|---|---|
| `API_BASE_URL`, `API_HOST` | your deployment |
| `CERT_PINS` | SHA-256 of the SubjectPublicKeyInfo of your intermediate, plus a backup |
| `network_security_config.xml` | the same host |

Get the pin with:

```bash
openssl s_client -connect api.example.invalid:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

Register the release signing certificate's SHA-256 digest with the backend as
`ACS_ANDROID_CERT_DIGEST`, and set `ACS_PLAY_INTEGRITY_PACKAGE_NAME` to the
application id. Without both, Play Integrity verification cannot bind a
verdict to this app.

[screenshot: enrolment screen]
[screenshot: door list]
[screenshot: unlock screen]
