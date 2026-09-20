#include "acs_beacon.h"

#include <NimBLEDevice.h>
#include <time.h>

#include "acs_crypto.h"
#include "config.h"

namespace acs {

Beacon beacon;

namespace {
const char kDomain[] = "acs-beacon:v1";
constexpr size_t kIdBytes = 16;
// 2024-01-01. Anything earlier means SNTP has not answered yet.
constexpr time_t kClockSane = 1704067200;
}  // namespace

void Beacon::begin() {
    if (started_) {
        return;
    }
    NimBLEDevice::init(ACS_CONTROLLER_CODE);
    NimBLEDevice::setPower(ESP_PWR_LVL_P3);
    started_ = true;
}

void Beacon::tick() {
    if (!started_) {
        return;
    }

    const time_t now = time(nullptr);
    if (now < kClockSane) {
        if (advertising_) {
            NimBLEDevice::getAdvertising()->stop();
            advertising_ = false;
        }
        return;
    }

    const uint64_t slot = static_cast<uint64_t>(now) / ACS_BEACON_ROTATION_S;
    if (advertising_ && slot == currentSlot_) {
        return;
    }
    updateAdvertisement(slot);
}

void Beacon::updateAdvertisement(uint64_t slot) {
    uint8_t message[sizeof(kDomain) - 1 + 8];
    memcpy(message, kDomain, sizeof(kDomain) - 1);
    for (int i = 0; i < 8; ++i) {
        message[sizeof(kDomain) - 1 + i] =
            static_cast<uint8_t>((slot >> (56 - 8 * i)) & 0xFF);
    }

    uint8_t mac[32];
    hmacSha256(ACS_BEACON_KEY, sizeof(ACS_BEACON_KEY), message, sizeof(message), mac);

    currentSlot_ = slot;
    currentId_ = base64UrlEncodeNoPad(mac, kIdBytes);

    // Manufacturer data: 0xFFFF is the "no company assigned" identifier,
    // which is the correct thing to use for a private protocol.
    std::string payload;
    payload.push_back(static_cast<char>(0xFF));
    payload.push_back(static_cast<char>(0xFF));
    payload.append(reinterpret_cast<const char *>(mac), kIdBytes);

    NimBLEAdvertising *advertising = NimBLEDevice::getAdvertising();
    advertising->stop();

    NimBLEAdvertisementData data;
    data.setFlags(BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP);
    data.setManufacturerData(payload);
    advertising->setAdvertisementData(data);

    // Non-connectable. There is nothing on this board for a phone to connect
    // to, so it does not accept connections.
    advertising->setAdvertisementType(BLE_GAP_CONN_MODE_NON);
    advertising->setMinInterval(160);   // 100 ms
    advertising->setMaxInterval(320);   // 200 ms
    advertising->start();
    advertising_ = true;
}

}  // namespace acs
