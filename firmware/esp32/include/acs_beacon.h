#pragma once

#include <Arduino.h>

namespace acs {

// The rotating BLE beacon.
//
// Advertises a 16 byte identifier derived from the shared beacon key and the
// current 30 second slot:
//
//     id(slot) = HMAC-SHA256(beacon_key, "acs-beacon:v1" || slot)[:16]
//
// A phone that can report a current identifier was within Bluetooth range of
// this door recently. It is not a secret the phone holds; it is an
// observation the phone can only have made by being there.
//
// If the controller's clock is not synchronised the beacon is not advertised
// at all, because an identifier from the wrong slot would simply be rejected
// by the server and a silent beacon is a clearer failure than a useless one.
class Beacon {
 public:
    void begin();
    void tick();
    bool isAdvertising() const { return advertising_; }
    String currentIdentifier() const { return currentId_; }

 private:
    void updateAdvertisement(uint64_t slot);

    bool started_ = false;
    bool advertising_ = false;
    uint64_t currentSlot_ = 0;
    String currentId_;
};

extern Beacon beacon;

}  // namespace acs
