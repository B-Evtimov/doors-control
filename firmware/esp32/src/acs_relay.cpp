#include "acs_relay.h"

#include "config.h"

namespace acs {

Relay relay;

namespace {
constexpr uint8_t kOn = ACS_RELAY_ACTIVE_HIGH ? HIGH : LOW;
constexpr uint8_t kOff = ACS_RELAY_ACTIVE_HIGH ? LOW : HIGH;
}  // namespace

void Relay::begin() {
    // Drive the pin to the safe level before switching it to an output, so
    // that the brief float at boot does not click the relay.
    digitalWrite(ACS_PIN_RELAY, kOff);
    pinMode(ACS_PIN_RELAY, OUTPUT);
    digitalWrite(ACS_PIN_RELAY, kOff);
    energised_ = false;
}

uint32_t Relay::pulse(uint32_t requestedMs) {
    const uint32_t duration = requestedMs > ACS_RELAY_MAX_MS ? ACS_RELAY_MAX_MS : requestedMs;
    digitalWrite(ACS_PIN_RELAY, kOn);
    energised_ = true;
    offAtMs_ = millis() + duration;
    return duration;
}

void Relay::tick() {
    if (!energised_) {
        return;
    }
    // Unsigned subtraction, so this stays correct across the millis() wrap.
    if (static_cast<int32_t>(millis() - offAtMs_) >= 0) {
        forceOff();
    }
}

void Relay::forceOff() {
    digitalWrite(ACS_PIN_RELAY, kOff);
    energised_ = false;
}

}  // namespace acs
