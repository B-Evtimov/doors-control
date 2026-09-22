#include "acs_ws.h"

#include <ArduinoJson.h>
#include <WebSocketsClient.h>
#include <time.h>

#include "acs_beacon.h"
#include "acs_command.h"
#include "acs_crypto.h"
#include "acs_relay.h"
#include "acs_status_led.h"
#include "config.h"

namespace acs {

WsLink wsLink;

namespace {

WebSocketsClient socketClient;

const char kAuthDomain[] = "acs-controller-auth:v1";
constexpr size_t kMaxCanonical = 512;

// The library takes a plain function pointer, so this forwards into the one
// link object.
void onWebSocketEvent(WStype_t type, uint8_t *payload, size_t length) {
    wsLink.handleEvent(static_cast<int>(type), payload, length);
}

}  // namespace

void WsLink::begin() {
    socketClient.beginSslWithCA(ACS_SERVER_HOST, ACS_SERVER_PORT, ACS_SERVER_PATH,
                                ACS_SERVER_ROOT_CA_PEM);
    socketClient.onEvent(onWebSocketEvent);
    // Reconnect on a fixed interval. A door that has lost the server stays
    // locked in the meantime; it does not fall back to anything.
    socketClient.setReconnectInterval(5000);
    socketClient.enableHeartbeat(15000, 5000, 3);
    lastPongMs_ = millis();
    statusLed.set(LedState::ServerConnecting);
}

void WsLink::tick() {
    socketClient.loop();

    if (authenticated_ &&
        (millis() - lastPongMs_) > (ACS_WS_HEARTBEAT_TIMEOUT_S * 1000UL)) {
        // Silence for longer than the heartbeat window means the link is gone
        // even though TCP has not noticed. Drop it and let the reconnect run.
        authenticated_ = false;
        socketClient.disconnect();
        statusLed.set(LedState::ServerConnecting);
    }
}

void WsLink::handleEvent(int type, uint8_t *payload, size_t length) {
    switch (type) {
        case WStype_CONNECTED:
            authenticated_ = false;
            lastPongMs_ = millis();
            statusLed.set(LedState::ServerConnecting);
            break;

        case WStype_DISCONNECTED:
            authenticated_ = false;
            statusLed.set(LedState::ServerConnecting);
            break;

        case WStype_TEXT:
            lastPongMs_ = millis();
            handleText(reinterpret_cast<const char *>(payload), length);
            break;

        case WStype_PONG:
            lastPongMs_ = millis();
            break;

        default:
            break;
    }
}

void WsLink::handleText(const char *text, size_t length) {
    JsonDocument document;
    if (deserializeJson(document, text, length) != DeserializationError::Ok) {
        return;
    }

    const char *type = document["type"] | "";

    if (strcmp(type, "challenge") == 0) {
        handleChallenge(document["nonce"] | "");
    } else if (strcmp(type, "auth_ok") == 0) {
        authenticated_ = true;
        lastPongMs_ = millis();
        statusLed.set(LedState::Online);
    } else if (strcmp(type, "ping") == 0) {
        socketClient.sendTXT("{\"type\":\"pong\"}");
    } else if (strcmp(type, "command") == 0) {
        handleCommand(text, length);
    }
}

void WsLink::handleChallenge(const char *nonceB64) {
    uint8_t nonce[64];
    const size_t nonceLength = base64Decode(String(nonceB64), nonce, sizeof(nonce));
    if (nonceLength == 0) {
        return;
    }

    // "acs-controller-auth:v1\0" + controller_code + "\0" + nonce
    uint8_t message[128];
    size_t offset = 0;
    memcpy(message, kAuthDomain, sizeof(kAuthDomain));  // includes the NUL
    offset += sizeof(kAuthDomain);

    const size_t codeLength = strlen(ACS_CONTROLLER_CODE);
    if (offset + codeLength + 1 + nonceLength > sizeof(message)) {
        return;
    }
    memcpy(message + offset, ACS_CONTROLLER_CODE, codeLength);
    offset += codeLength;
    message[offset++] = 0x00;
    memcpy(message + offset, nonce, nonceLength);
    offset += nonceLength;

    uint8_t signature[64];
    signWithControllerKey(message, offset, signature);

    JsonDocument response;
    response["type"] = "auth";
    response["controller_code"] = ACS_CONTROLLER_CODE;
    response["signature"] = base64Encode(signature, sizeof(signature));
    response["firmware_version"] = ACS_FIRMWARE_VERSION;

    String out;
    serializeJson(response, out);
    socketClient.sendTXT(out);
}

void WsLink::handleCommand(const char *text, size_t length) {
    JsonDocument document;
    if (deserializeJson(document, text, length) != DeserializationError::Ok) {
        return;
    }

    UnlockCommand command;
    if (!parseUnlockCommand(document["payload"].as<JsonObjectConst>(), command)) {
        statusLed.set(LedState::Rejected);
        return;
    }

    // A command for a different controller is refused even though it is
    // correctly signed. The signature says the server issued it; the code
    // says whose door it is for.
    if (command.controllerCode != ACS_CONTROLLER_CODE) {
        sendAck(command.commandId, "rejected", "wrong_controller", 0);
        statusLed.set(LedState::Rejected);
        return;
    }

    uint8_t signature[64];
    const String signatureB64 = document["signature"] | "";
    if (base64Decode(signatureB64, signature, sizeof(signature)) != sizeof(signature)) {
        sendAck(command.commandId, "rejected", "bad_signature_encoding", 0);
        statusLed.set(LedState::Rejected);
        return;
    }

    uint8_t canonical[kMaxCanonical];
    const size_t canonicalLength = canonicalCommandBytes(command, canonical, sizeof(canonical));
    if (canonicalLength == 0) {
        sendAck(command.commandId, "rejected", "command_too_large", 0);
        statusLed.set(LedState::Rejected);
        return;
    }

    if (!verifySignature(ACS_SIGNER_PUBLIC_KEY, signature, canonical, canonicalLength)) {
        // This is the line that makes a compromised server not enough. The
        // signing key lives in a process with no network; nothing that
        // reaches this board over the wire can produce a valid signature.
        sendAck(command.commandId, "rejected", "bad_signature", 0);
        statusLed.set(LedState::Rejected);
        return;
    }

    const time_t now = time(nullptr);
    if (now < 1704067200) {
        sendAck(command.commandId, "rejected", "clock_not_synced", 0);
        statusLed.set(LedState::Rejected);
        return;
    }
    if (command.expiresAt < static_cast<int64_t>(now) - ACS_MAX_CLOCK_SKEW_S) {
        // Freshness is not part of the signature, which is why it is checked
        // separately: a recorded command stays correctly signed forever.
        sendAck(command.commandId, "rejected", "expired", 0);
        statusLed.set(LedState::Rejected);
        return;
    }
    if (command.issuedAt > static_cast<int64_t>(now) + ACS_MAX_CLOCK_SKEW_S) {
        sendAck(command.commandId, "rejected", "issued_in_the_future", 0);
        statusLed.set(LedState::Rejected);
        return;
    }

    if (commandAlreadySeen(command.commandId)) {
        sendAck(command.commandId, "rejected", "replayed", 0);
        statusLed.set(LedState::Rejected);
        return;
    }
    rememberCommand(command.commandId);

    const uint32_t relayMs = relay.pulse(command.durationMs);
    statusLed.set(LedState::Unlocking);
    sendAck(command.commandId, "opened", "ok", relayMs);
}

void WsLink::sendAck(const String &commandId, const char *result, const char *detail,
                     uint32_t relayMs) {
    JsonDocument ack;
    ack["type"] = "ack";
    ack["command_id"] = commandId;
    ack["result"] = result;
    ack["detail"] = detail;
    ack["relay_ms"] = relayMs;
    ack["uptime_ms"] = millis();

    String out;
    serializeJson(ack, out);
    socketClient.sendTXT(out);
}

void WsLink::sendEvent(const char *event, const char *outcome, const String &detailJson) {
    if (!authenticated_) {
        return;
    }
    String out = "{\"type\":\"event\",\"event\":\"";
    out += event;
    out += "\",\"outcome\":\"";
    out += outcome;
    out += "\",\"detail\":";
    out += detailJson.length() ? detailJson : String("{}");
    out += "}";
    socketClient.sendTXT(out);
}

bool WsLink::commandAlreadySeen(const String &commandId) {
    for (size_t i = 0; i < kSeenCapacity; ++i) {
        if (seen_[i].length() && seen_[i] == commandId) {
            return true;
        }
    }
    return false;
}

void WsLink::rememberCommand(const String &commandId) {
    seen_[seenNext_] = commandId;
    seenNext_ = (seenNext_ + 1) % kSeenCapacity;
}

}  // namespace acs
