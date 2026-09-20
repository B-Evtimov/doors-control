#pragma once

#include <Arduino.h>

namespace acs {

// The relay driver.
//
// Two rules the rest of the firmware cannot break:
//   * the pulse length is clamped to ACS_RELAY_MAX_MS whatever it is asked for
//   * any reset, hang or power loss leaves the relay de-energised, which means
//     the door is locked. There is no state in which the firmware holds a door
//     open across a restart.
class Relay {
 public:
    void begin();
    // Returns the pulse length actually used, in milliseconds.
    uint32_t pulse(uint32_t requestedMs);
    void tick();
    bool isEnergised() const { return energised_; }
    void forceOff();

 private:
    bool energised_ = false;
    uint32_t offAtMs_ = 0;
};

extern Relay relay;

}  // namespace acs
