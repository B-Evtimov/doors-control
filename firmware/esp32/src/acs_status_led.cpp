#include "acs_status_led.h"

#include "config.h"

namespace acs {

StatusLed statusLed;

void StatusLed::begin() {
    pinMode(ACS_PIN_LED_STATUS, OUTPUT);
    digitalWrite(ACS_PIN_LED_STATUS, LOW);
}

void StatusLed::set(LedState state) {
    if (state_ == state) {
        return;
    }
    state_ = state;
    phase_ = 0;
    nextChangeMs_ = millis();
}

void StatusLed::tick() {
    const uint32_t now = millis();
    if (static_cast<int32_t>(now - nextChangeMs_) < 0) {
        return;
    }

    uint32_t hold = 500;
    switch (state_) {
        case LedState::Booting:
        case LedState::WifiConnecting:
            level_ = !level_;
            hold = 100;
            break;
        case LedState::ServerConnecting:
            level_ = !level_;
            hold = 500;
            break;
        case LedState::Online:
            level_ = true;
            hold = 1000;
            break;
        case LedState::Unlocking:
            level_ = true;
            hold = 3000;
            break;
        case LedState::Rejected:
            level_ = !level_;
            hold = 120;
            if (++phase_ >= 6) {
                state_ = LedState::Online;
                level_ = true;
            }
            break;
    }

    digitalWrite(ACS_PIN_LED_STATUS, level_ ? HIGH : LOW);
    nextChangeMs_ = now + hold;
}

}  // namespace acs
