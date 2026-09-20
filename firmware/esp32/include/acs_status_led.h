#pragma once

#include <Arduino.h>

namespace acs {

// What the LED is saying:
//   solid off          no power, or the board is held in reset
//   fast blink 5 Hz    joining Wi-Fi
//   slow blink 1 Hz    Wi-Fi up, connecting or authenticating to the server
//   solid on           connected and authenticated, waiting for commands
//   two short pulses   a command was refused
//   long on 3 s        the relay is energised
enum class LedState { Booting, WifiConnecting, ServerConnecting, Online, Rejected, Unlocking };

class StatusLed {
 public:
    void begin();
    void set(LedState state);
    void tick();

 private:
    LedState state_ = LedState::Booting;
    uint32_t nextChangeMs_ = 0;
    uint8_t phase_ = 0;
    bool level_ = false;
};

extern StatusLed statusLed;

}  // namespace acs
