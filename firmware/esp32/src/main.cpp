// ---------------------------------------------------------------------------
//  Evtimov Doors Control System - ESP32 door controller
//
//  Boots into the locked state, joins Wi-Fi, syncs the clock, starts the BLE
//  beacon, dials out to the backend and waits. It has no inbound port, no
//  local unlock path and no stored credential that would let anyone else open
//  the door - only a private key that proves which controller it is.
//
//  Every path that fails leaves the door locked. There is no branch in this
//  firmware that opens a relay without a signature it has verified itself.
// ---------------------------------------------------------------------------

#include <Arduino.h>
#include <WiFi.h>
#include <esp_task_wdt.h>
#include <time.h>

#include "acs_beacon.h"
#include "acs_ota.h"
#include "acs_relay.h"
#include "acs_status_led.h"
#include "acs_ws.h"
#include "config.h"

namespace {

bool tamperLatched = false;
uint32_t lastSenseReportMs = 0;
bool lastDoorClosed = true;

void configureWatchdog() {
    // A hung task resets the board. The reset itself de-energises the relay,
    // so a hang cannot leave a door standing open.
#if ESP_IDF_VERSION_MAJOR >= 5
    esp_task_wdt_config_t config = {
        .timeout_ms = ACS_WATCHDOG_S * 1000,
        .idle_core_mask = 0,
        .trigger_panic = true,
    };
    esp_task_wdt_init(&config);
#else
    esp_task_wdt_init(ACS_WATCHDOG_S, true);
#endif
    esp_task_wdt_add(nullptr);
}

void joinWifi() {
    acs::statusLed.set(acs::LedState::WifiConnecting);
    WiFi.persistent(false);
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    WiFi.setAutoReconnect(true);
    WiFi.begin(ACS_WIFI_SSID, ACS_WIFI_PASSWORD);
}

void syncClock() {
    // The clock is a security control here: it is what makes an expired
    // command expired and what selects the current beacon slot.
    configTime(0, 0, ACS_NTP_SERVER_1, ACS_NTP_SERVER_2);
}

void readInputs() {
    if (millis() - lastSenseReportMs < 1000) {
        return;
    }
    lastSenseReportMs = millis();

    const bool tamperOpen = digitalRead(ACS_PIN_TAMPER) == HIGH;
    if (tamperOpen && !tamperLatched) {
        tamperLatched = true;
        acs::wsLink.sendEvent("tamper", "failure", "{\"state\":\"open\"}");
    }

    const bool doorClosed = digitalRead(ACS_PIN_DOOR_SENSE) == LOW;
    if (doorClosed != lastDoorClosed) {
        lastDoorClosed = doorClosed;
        acs::wsLink.sendEvent("door_sense", "success",
                              doorClosed ? "{\"state\":\"closed\"}" : "{\"state\":\"open\"}");
    }
}

}  // namespace

void setup() {
    Serial.begin(115200);

    // Before anything else. If the board resets in the middle of a pulse,
    // this is what puts the lock back.
    acs::relay.begin();
    acs::statusLed.begin();

    pinMode(ACS_PIN_DOOR_SENSE, INPUT_PULLUP);
    pinMode(ACS_PIN_TAMPER, INPUT_PULLUP);

    configureWatchdog();

    Serial.printf("acs controller %s firmware %s\n",
                  ACS_CONTROLLER_CODE, ACS_FIRMWARE_VERSION);

    joinWifi();
    syncClock();

    acs::beacon.begin();
    acs::ota.begin();
}

void loop() {
    esp_task_wdt_reset();

    static bool linkStarted = false;
    if (WiFi.status() == WL_CONNECTED) {
        if (!linkStarted) {
            acs::wsLink.begin();
            linkStarted = true;
        }
    } else {
        acs::statusLed.set(acs::LedState::WifiConnecting);
    }

    acs::relay.tick();
    acs::statusLed.tick();
    acs::beacon.tick();

    if (linkStarted) {
        acs::wsLink.tick();
        acs::ota.tick();
        readInputs();
    }

    delay(5);
}
