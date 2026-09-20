#include "acs_crypto.h"

#include <Ed25519.h>
#include <mbedtls/base64.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#include "config.h"

namespace acs {

void signWithControllerKey(const uint8_t *message, size_t length, uint8_t signature[64]) {
    Ed25519::sign(signature, ACS_CONTROLLER_PRIVATE_KEY, ACS_CONTROLLER_PUBLIC_KEY,
                  message, length);
}

bool verifySignature(const uint8_t publicKey[32], const uint8_t signature[64],
                     const uint8_t *message, size_t length) {
    return Ed25519::verify(signature, publicKey, message, length);
}

void hmacSha256(const uint8_t *key, size_t keyLength,
                const uint8_t *data, size_t dataLength,
                uint8_t out[32]) {
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, key, keyLength);
    mbedtls_md_hmac_update(&ctx, data, dataLength);
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

void sha256(const uint8_t *data, size_t length, uint8_t out[32]) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, data, length);
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);
}

size_t base64Decode(const String &input, uint8_t *out, size_t outCapacity) {
    size_t written = 0;
    const int rc = mbedtls_base64_decode(
        out, outCapacity, &written,
        reinterpret_cast<const unsigned char *>(input.c_str()), input.length());
    return rc == 0 ? written : 0;
}

String base64Encode(const uint8_t *data, size_t length) {
    size_t needed = 0;
    mbedtls_base64_encode(nullptr, 0, &needed, data, length);
    String result;
    result.reserve(needed + 1);
    uint8_t buffer[128];
    if (needed > sizeof(buffer)) {
        return String();
    }
    size_t written = 0;
    if (mbedtls_base64_encode(buffer, sizeof(buffer), &written, data, length) != 0) {
        return String();
    }
    buffer[written] = '\0';
    result = reinterpret_cast<const char *>(buffer);
    return result;
}

String base64UrlEncodeNoPad(const uint8_t *data, size_t length) {
    String encoded = base64Encode(data, length);
    encoded.replace('+', '-');
    encoded.replace('/', '_');
    while (encoded.endsWith("=")) {
        encoded.remove(encoded.length() - 1);
    }
    return encoded;
}

bool equalsConstantTime(const uint8_t *a, const uint8_t *b, size_t length) {
    uint8_t difference = 0;
    for (size_t i = 0; i < length; ++i) {
        difference |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return difference == 0;
}

}  // namespace acs
