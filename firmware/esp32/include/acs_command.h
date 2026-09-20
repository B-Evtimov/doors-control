#pragma once

#include <Arduino.h>
#include <ArduinoJson.h>

namespace acs {

// Rebuilding the exact bytes the server signed.
//
// The signature covers
//
//     "acs-command:v1\0" + compact JSON with the keys in sorted order
//
// which on the server side is
//
//     json.dumps(payload, sort_keys=True, separators=(",", ":"))
//
// The firmware does not re-serialise whatever ArduinoJson parsed, because a
// parser is free to normalise things a signature is not. It writes the fields
// out itself, in the one order both sides agree on:
//
//     cmd, command_id, controller_code, door_code, duration_ms,
//     expires_at, issued_at, nonce, relay_channel
//
// A command containing a field this firmware does not know about therefore
// fails verification rather than being silently accepted with the unknown
// part ignored.
struct UnlockCommand {
    String commandId;
    String controllerCode;
    String doorCode;
    uint32_t durationMs = 0;
    uint32_t relayChannel = 0;
    int64_t issuedAt = 0;
    int64_t expiresAt = 0;
    String nonce;
};

bool parseUnlockCommand(JsonObjectConst payload, UnlockCommand &out);

// Writes the canonical bytes into buffer. Returns the number written, or 0 if
// the buffer is too small.
size_t canonicalCommandBytes(const UnlockCommand &command, uint8_t *buffer, size_t capacity);

}  // namespace acs
