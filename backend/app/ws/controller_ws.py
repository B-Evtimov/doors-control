"""The controller side of the connection.

Handshake, in order:

    server -> {"type":"challenge","nonce":"<base64>","server_time":<unix>}
    client -> {"type":"auth","controller_code":"...","signature":"<base64>",
               "firmware_version":"1.0.0"}
    server -> {"type":"auth_ok","heartbeat":25,"signer_key_id":"signer-1"}

The signature is Ed25519 over

    b"acs-controller-auth:v1\\x00" || controller_code || b"\\x00" || nonce

with the controller's private key, checked against the public key stored in
the database at provisioning time. The nonce is fresh per connection, so a
recorded handshake cannot be replayed. Note the direction: the server proves
nothing to the controller here, because TLS already did - the controller
verifies the server's certificate against a pinned CA before it sends
anything.

After that the socket stays open. The server pings; a controller that stops
answering is dropped and its doors report offline, which fails closed.
"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.api.deps import Services
from app.core.errors import AuditEvent
from app.ws.hub import ControllerSession

router = APIRouter()

AUTH_DOMAIN = b"acs-controller-auth:v1\x00"
MAX_MESSAGE_BYTES = 16 * 1024


def auth_message(controller_code: str, nonce: bytes) -> bytes:
    return AUTH_DOMAIN + controller_code.encode("utf-8") + b"\x00" + nonce


@router.websocket("/ws/controller")
async def controller_socket(websocket: WebSocket) -> None:
    services: Services = websocket.app.state.services
    settings = services.settings
    peer = websocket.client.host if websocket.client else None

    await websocket.accept()

    nonce = secrets.token_bytes(32)
    await websocket.send_text(
        json.dumps(
            {
                "type": "challenge",
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "server_time": int(time.time()),
            },
            separators=(",", ":"),
        )
    )

    try:
        raw = await asyncio.wait_for(
            websocket.receive_text(), settings.ws_handshake_timeout_seconds
        )
    except (TimeoutError, WebSocketDisconnect):
        await websocket.close(code=4408)
        return

    controller = None
    try:
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ValueError("handshake too large")
        message = json.loads(raw)
        if message.get("type") != "auth":
            raise ValueError("expected auth")
        code = str(message["controller_code"])
        signature = base64.b64decode(message["signature"], validate=True)

        controller = await services.controllers.by_code(code)
        if controller is None or controller["is_blocked"]:
            raise ValueError("unknown or blocked controller")

        Ed25519PublicKey.from_public_bytes(bytes(controller["public_key"])).verify(
            signature, auth_message(code, nonce)
        )
    except (ValueError, KeyError, InvalidSignature, json.JSONDecodeError) as exc:
        await services.audit.failure(
            AuditEvent.CONTROLLER_AUTH_FAILED,
            actor_type="controller",
            controller_id=controller["id"] if controller else None,
            client_ip=peer,
            detail={"reason": type(exc).__name__},
        )
        await websocket.close(code=4401)
        return

    firmware = message.get("firmware_version")
    await services.controllers.touch_seen(
        controller["id"], ip=peer, firmware_version=firmware
    )
    await services.audit.success(
        AuditEvent.CONTROLLER_CONNECTED,
        actor_type="controller",
        controller_id=controller["id"],
        client_ip=peer,
        detail={"controller_code": controller["code"], "firmware_version": firmware},
    )

    await websocket.send_text(
        json.dumps(
            {
                "type": "auth_ok",
                "heartbeat": settings.ws_heartbeat_seconds,
                "signer_key_id": settings.signer_key_id,
            },
            separators=(",", ":"),
        )
    )

    session = ControllerSession(
        controller_id=controller["id"],
        controller_code=controller["code"],
        send=websocket.send_text,
        remote_ip=peer,
        firmware_version=firmware,
    )
    await services.hub.register(session)

    heartbeat = asyncio.create_task(_heartbeat(websocket, session, settings))
    try:
        while True:
            raw = await websocket.receive_text()
            if len(raw) > MAX_MESSAGE_BYTES:
                break
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue

            kind = message.get("type")
            if kind == "pong":
                session.last_pong_at = time.time()
                await services.controllers.touch_seen(controller["id"], ip=peer)
            elif kind == "ack":
                services.hub.resolve(session, message)
            elif kind == "event":
                # Tamper switch, watchdog reset, relay driven locally - all of
                # it lands in the same audit log as everything else.
                await services.audit.record(
                    f'controller.{message.get("event", "unknown")}',
                    message.get("outcome", "success"),
                    actor_type="controller",
                    controller_id=controller["id"],
                    client_ip=peer,
                    detail={"payload": message.get("detail", {})},
                )
    except WebSocketDisconnect:
        pass
    finally:
        heartbeat.cancel()
        await services.hub.unregister(session.controller_code, session)
        await services.audit.record(
            AuditEvent.CONTROLLER_DISCONNECTED,
            "success",
            actor_type="controller",
            controller_id=controller["id"],
            client_ip=peer,
            detail={"connected_seconds": int(time.time() - session.connected_at)},
        )


async def _heartbeat(websocket: WebSocket, session: ControllerSession, settings) -> None:
    ping = json.dumps({"type": "ping"}, separators=(",", ":"))
    try:
        while True:
            await asyncio.sleep(settings.ws_heartbeat_seconds)
            if time.time() - session.last_pong_at > settings.ws_heartbeat_timeout_seconds:
                await websocket.close(code=4408)
                return
            await websocket.send_text(ping)
    except (asyncio.CancelledError, RuntimeError, WebSocketDisconnect):
        return
