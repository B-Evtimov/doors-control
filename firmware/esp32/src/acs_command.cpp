#include "acs_command.h"

#include <string.h>

namespace acs {

namespace {

// JSON string escaping, limited to what these fields can contain. Every value
// in a command is either an identifier, a UUID or base64, so the only
// characters needing an escape are the ones a malformed server would send -
// and if one shows up, failing to match the signature is the correct outcome.
void appendJsonString(String &out, const String &value) {
    out += '"';
    for (size_t i = 0; i < value.length(); ++i) {
        const char c = value[i];
        if (c == '"' || c == '\\') {
            out += '\\';
            out += c;
        } else if (static_cast<uint8_t>(c) < 0x20) {
            char escape[7];
            snprintf(escape, sizeof(escape), "\\u%04x", c);
            out += escape;
        } else {
            out += c;
        }
    }
    out += '"';
}

}  // namespace

bool parseUnlockCommand(JsonObjectConst payload, UnlockCommand &out) {
    if (!payload["command_id"].is<const char *>() ||
        !payload["cmd"].is<const char *>() ||
        !payload["controller_code"].is<const char *>() ||
        !payload["door_code"].is<const char *>() ||
        !payload["nonce"].is<const char *>() ||
        !payload["duration_ms"].is<uint32_t>() ||
        !payload["relay_channel"].is<uint32_t>() ||
        !payload["issued_at"].is<int64_t>() ||
        !payload["expires_at"].is<int64_t>()) {
        return false;
    }

    if (strcmp(payload["cmd"].as<const char *>(), "unlock") != 0) {
        return false;
    }

    out.commandId = payload["command_id"].as<const char *>();
    out.controllerCode = payload["controller_code"].as<const char *>();
    out.doorCode = payload["door_code"].as<const char *>();
    out.nonce = payload["nonce"].as<const char *>();
    out.durationMs = payload["duration_ms"].as<uint32_t>();
    out.relayChannel = payload["relay_channel"].as<uint32_t>();
    out.issuedAt = payload["issued_at"].as<int64_t>();
    out.expiresAt = payload["expires_at"].as<int64_t>();
    return true;
}

size_t canonicalCommandBytes(const UnlockCommand &command, uint8_t *buffer, size_t capacity) {
    static const char kDomain[] = "acs-command:v1";

    String body;
    body.reserve(320);
    body += '{';
    body += "\"cmd\":\"unlock\",";
    body += "\"command_id\":";
    appendJsonString(body, command.commandId);
    body += ",\"controller_code\":";
    appendJsonString(body, command.controllerCode);
    body += ",\"door_code\":";
    appendJsonString(body, command.doorCode);
    body += ",\"duration_ms\":";
    body += String(command.durationMs);
    body += ",\"expires_at\":";
    body += String(static_cast<long long>(command.expiresAt));
    body += ",\"issued_at\":";
    body += String(static_cast<long long>(command.issuedAt));
    body += ",\"nonce\":";
    appendJsonString(body, command.nonce);
    body += ",\"relay_channel\":";
    body += String(command.relayChannel);
    body += '}';

    const size_t domainLength = sizeof(kDomain);  // includes the NUL separator
    const size_t total = domainLength + body.length();
    if (total > capacity) {
        return 0;
    }

    memcpy(buffer, kDomain, domainLength);
    memcpy(buffer + domainLength, body.c_str(), body.length());
    return total;
}

}  // namespace acs
