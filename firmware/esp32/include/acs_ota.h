#pragma once

#include <Arduino.h>

namespace acs {

// Signed over-the-air updates.
//
// The board fetches a small JSON manifest over HTTPS, and the manifest is
// itself signed. What is signed is the SHA-256 of the image plus its version
// and size, with a key that is not the command signing key - so a stolen
// command key cannot push firmware, and a stolen firmware key cannot open a
// door.
//
// The image is streamed into the inactive OTA slot and hashed as it arrives.
// The signature is checked against the completed hash before the boot
// partition is switched. A failed check leaves the running firmware exactly
// where it was, and a failed boot rolls back to it.
//
// Set ACS_OTA_MANIFEST_URL to "" to compile this out of the decision path
// entirely: a door that never checks for updates cannot be attacked through
// its update path.
class OtaUpdater {
 public:
    void begin();
    void tick();
    bool checkNow();

 private:
    bool applyUpdate(const String &url, const uint8_t expectedSha[32],
                     const uint8_t signature[64], size_t imageSize,
                     const String &version);

    uint32_t nextCheckMs_ = 0;
    bool enabled_ = false;
};

extern OtaUpdater ota;

}  // namespace acs
