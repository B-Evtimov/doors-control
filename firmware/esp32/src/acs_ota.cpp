#include "acs_ota.h"

#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <Update.h>
#include <WiFiClientSecure.h>
#include <mbedtls/sha256.h>

#include "acs_crypto.h"
#include "acs_ws.h"
#include "config.h"

namespace acs {

OtaUpdater ota;

namespace {
constexpr size_t kChunk = 1024;
}  // namespace

void OtaUpdater::begin() {
    enabled_ = strlen(ACS_OTA_MANIFEST_URL) > 0;
    nextCheckMs_ = millis() + 60UL * 1000UL;
}

void OtaUpdater::tick() {
    if (!enabled_) {
        return;
    }
    if (static_cast<int32_t>(millis() - nextCheckMs_) < 0) {
        return;
    }
    nextCheckMs_ = millis() + ACS_OTA_CHECK_HOURS * 3600UL * 1000UL;
    checkNow();
}

bool OtaUpdater::checkNow() {
    WiFiClientSecure client;
    client.setCACert(ACS_SERVER_ROOT_CA_PEM);

    HTTPClient http;
    if (!http.begin(client, ACS_OTA_MANIFEST_URL)) {
        return false;
    }
    const int code = http.GET();
    if (code != HTTP_CODE_OK) {
        http.end();
        return false;
    }

    JsonDocument manifest;
    const DeserializationError error = deserializeJson(manifest, http.getString());
    http.end();
    if (error != DeserializationError::Ok) {
        return false;
    }

    const String version = manifest["version"] | "";
    if (version.length() == 0 || version == ACS_FIRMWARE_VERSION) {
        return false;
    }

    const String url = manifest["url"] | "";
    const size_t size = manifest["size"] | 0;
    if (url.length() == 0 || size == 0) {
        return false;
    }

    uint8_t expectedSha[32];
    uint8_t signature[64];
    if (base64Decode(manifest["sha256"] | "", expectedSha, sizeof(expectedSha)) != 32) {
        return false;
    }
    if (base64Decode(manifest["signature"] | "", signature, sizeof(signature)) != 64) {
        return false;
    }

    // What is signed: the domain, the version, the size and the hash. Signing
    // the hash alone would let an attacker keep a valid signature while
    // serving a different, smaller image under a different version string.
    String signedText = "acs-ota:v1|";
    signedText += version;
    signedText += "|";
    signedText += String(static_cast<unsigned long>(size));
    signedText += "|";
    signedText += manifest["sha256"].as<const char *>();

    if (!verifySignature(ACS_OTA_PUBLIC_KEY, signature,
                         reinterpret_cast<const uint8_t *>(signedText.c_str()),
                         signedText.length())) {
        wsLink.sendEvent("ota_rejected", "failure", "{\"reason\":\"bad_manifest_signature\"}");
        return false;
    }

    return applyUpdate(url, expectedSha, signature, size, version);
}

bool OtaUpdater::applyUpdate(const String &url, const uint8_t expectedSha[32],
                             const uint8_t signature[64], size_t imageSize,
                             const String &version) {
    (void)signature;

    WiFiClientSecure client;
    client.setCACert(ACS_SERVER_ROOT_CA_PEM);

    HTTPClient http;
    if (!http.begin(client, url)) {
        return false;
    }
    if (http.GET() != HTTP_CODE_OK) {
        http.end();
        return false;
    }

    if (!Update.begin(imageSize)) {
        http.end();
        return false;
    }

    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);

    WiFiClient *stream = http.getStreamPtr();
    uint8_t buffer[kChunk];
    size_t received = 0;

    while (http.connected() && received < imageSize) {
        const size_t available = stream->available();
        if (available == 0) {
            delay(1);
            continue;
        }
        const size_t toRead = available > kChunk ? kChunk : available;
        const int read = stream->readBytes(buffer, toRead);
        if (read <= 0) {
            break;
        }
        mbedtls_sha256_update(&sha, buffer, read);
        if (Update.write(buffer, read) != static_cast<size_t>(read)) {
            break;
        }
        received += read;
    }
    http.end();

    uint8_t actualSha[32];
    mbedtls_sha256_finish(&sha, actualSha);
    mbedtls_sha256_free(&sha);

    if (received != imageSize || !equalsConstantTime(actualSha, expectedSha, 32)) {
        Update.abort();
        wsLink.sendEvent("ota_rejected", "failure", "{\"reason\":\"hash_mismatch\"}");
        return false;
    }

    if (!Update.end(true)) {
        wsLink.sendEvent("ota_rejected", "failure", "{\"reason\":\"flash_failed\"}");
        return false;
    }

    String detail = "{\"version\":\"";
    detail += version;
    detail += "\"}";
    wsLink.sendEvent("ota_applied", "success", detail);

    delay(250);
    ESP.restart();
    return true;
}

}  // namespace acs
