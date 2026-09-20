#pragma once

#include <Arduino.h>
#include <stdint.h>

namespace acs {

// Ed25519 signature over an arbitrary message with this controller's key.
void signWithControllerKey(const uint8_t *message, size_t length, uint8_t signature[64]);

// Verify an Ed25519 signature against a 32 byte public key.
bool verifySignature(const uint8_t publicKey[32], const uint8_t signature[64],
                     const uint8_t *message, size_t length);

// HMAC-SHA256, used to derive the rotating beacon identifier.
void hmacSha256(const uint8_t *key, size_t keyLength,
                const uint8_t *data, size_t dataLength,
                uint8_t out[32]);

void sha256(const uint8_t *data, size_t length, uint8_t out[32]);

size_t base64Decode(const String &input, uint8_t *out, size_t outCapacity);
String base64Encode(const uint8_t *data, size_t length);
String base64UrlEncodeNoPad(const uint8_t *data, size_t length);

// Constant time comparison. Used wherever a mismatch must not be detectable
// by how long the comparison took.
bool equalsConstantTime(const uint8_t *a, const uint8_t *b, size_t length);

}  // namespace acs
