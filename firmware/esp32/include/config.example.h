// ---------------------------------------------------------------------------
//  Evtimov Doors Control System - controller configuration
//
//  Copy this file to config.h and fill it in. config.h is in .gitignore and
//  must never be committed: it contains this controller's private key.
//
//  Generate the key material with:
//      python -m signer.keygen --controller
//
//  That prints the public key and beacon key to register in the database, and
//  the C arrays to paste below. The private key exists in exactly two places:
//  the terminal you generated it in, and this file on the machine that flashes
//  the board. Close the terminal afterwards.
// ---------------------------------------------------------------------------

#pragma once

#include <stdint.h>

// --------------------------------------------------------------------- network
#define ACS_WIFI_SSID          "your-ssid"
#define ACS_WIFI_PASSWORD      "your-wifi-password"

// Host and path of the backend. WSS only; the firmware refuses plain ws://.
#define ACS_SERVER_HOST        "api.example.invalid"
#define ACS_SERVER_PORT        443
#define ACS_SERVER_PATH        "/ws/controller"

// Root certificate of the CA that issued the server's certificate, PEM.
// Pinning the CA rather than the leaf so that certificate renewal does not
// require reflashing every door. Replace with your own.
#define ACS_SERVER_ROOT_CA_PEM \
    "-----BEGIN CERTIFICATE-----\n" \
    "REPLACE_THIS_WITH_YOUR_CA_CERTIFICATE\n" \
    "-----END CERTIFICATE-----\n"

// --------------------------------------------------------------------- identity
#define ACS_CONTROLLER_CODE    "ctrl-example-01"
#define ACS_FIRMWARE_VERSION   "1.0.0"

// This controller's Ed25519 private key. Never leaves the board.
static const uint8_t ACS_CONTROLLER_PRIVATE_KEY[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// The matching public key. Registered in acs.controllers.public_key.
static const uint8_t ACS_CONTROLLER_PUBLIC_KEY[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Shared secret behind the rotating BLE beacon identifier. Registered in
// acs.controllers.beacon_key. The phone never holds this.
static const uint8_t ACS_BEACON_KEY[32] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
};

// Public key of the command signer. Every unlock command is verified against
// this before the relay is touched. Printed by `python -m signer.keygen`.
static const uint8_t ACS_SIGNER_PUBLIC_KEY[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Public key that signs firmware images. Kept separate from the command
// signer so that stealing one does not give the other.
static const uint8_t ACS_OTA_PUBLIC_KEY[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// ----------------------------------------------------------------------- pins
// ESP32-WROOM-32, 38 pin module.
#define ACS_PIN_RELAY          26   // through an opto-isolated relay module
#define ACS_PIN_LED_STATUS     2    // on-board LED
#define ACS_PIN_DOOR_SENSE     27   // optional reed switch, active low
#define ACS_PIN_TAMPER         14   // optional enclosure switch, active low

// Some relay boards are active low. Set to 0 if yours energises on LOW.
#define ACS_RELAY_ACTIVE_HIGH  1

// ------------------------------------------------------------------- behaviour
// Hard ceiling on how long the relay may be energised, whatever a command
// asks for. The server also caps this; the firmware does not rely on that.
#define ACS_RELAY_MAX_MS       3000

// Seconds without a pong before the connection is considered dead.
#define ACS_WS_HEARTBEAT_TIMEOUT_S  60

// Watchdog period. A hung task resets the board; the relay is de-energised by
// the reset itself, so a hang leaves the door locked.
#define ACS_WATCHDOG_S         15

// Rotation period of the BLE beacon identifier, seconds. Must match the
// server's ACS_BEACON_ROTATION_SECONDS.
#define ACS_BEACON_ROTATION_S  30

// How far the controller's clock may differ from a command's timestamps
// before the command is refused, seconds. Small on purpose.
#define ACS_MAX_CLOCK_SKEW_S   5

// NTP. The clock is what makes an expired command expired, so this matters.
#define ACS_NTP_SERVER_1       "pool.ntp.org"
#define ACS_NTP_SERVER_2       "time.cloudflare.com"

// Optional OTA manifest URL. Leave empty to disable update checks entirely.
#define ACS_OTA_MANIFEST_URL   ""
#define ACS_OTA_CHECK_HOURS    12
