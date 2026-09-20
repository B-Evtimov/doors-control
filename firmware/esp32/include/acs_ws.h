#pragma once

#include <Arduino.h>

namespace acs {

// The link to the backend.
//
// Outbound only. The controller dials wss://<host>/ws/controller and keeps
// the socket open; it never listens. There is no port to scan on this board
// and no inbound firewall rule anywhere for it, which is the single largest
// reduction in attack surface in the whole design.
//
// The server proves nothing to the controller over this protocol, because TLS
// already did: the certificate is validated against a CA pinned in config.h
// before a single byte of the handshake below is sent.
class WsLink {
 public:
    void begin();
    void tick();
    bool isAuthenticated() const { return authenticated_; }
    void sendEvent(const char *event, const char *outcome, const String &detailJson);

    // Called from the library's C-style callback. Public only for that.
    void handleEvent(int type, uint8_t *payload, size_t length);

 private:
    void handleText(const char *text, size_t length);
    void handleChallenge(const char *nonceB64);
    void handleCommand(const char *text, size_t length);
    void sendAck(const String &commandId, const char *result, const char *detail,
                 uint32_t relayMs);
    bool commandAlreadySeen(const String &commandId);
    void rememberCommand(const String &commandId);

    bool authenticated_ = false;
    uint32_t lastPongMs_ = 0;

    // A small ring of recently honoured command identifiers. Commands are
    // already single use because they expire in seconds, but replaying one
    // inside its own window would otherwise open the door twice.
    static constexpr size_t kSeenCapacity = 16;
    String seen_[kSeenCapacity];
    size_t seenNext_ = 0;
};

extern WsLink wsLink;

}  // namespace acs
