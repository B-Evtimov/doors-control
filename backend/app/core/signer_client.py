"""Client for the signer's Unix socket.

The API never holds the signing key. It asks for a signature over a command it
has already decided to issue, and it gets back bytes it cannot forge. If the
signer is down, no door opens - which is the correct failure direction.
"""

from __future__ import annotations

import asyncio
import base64
from typing import Any

from app.core.config import Settings
from signer.protocol import decode_line, encode_request


class SignerUnavailable(RuntimeError):
    pass


class SignerRefused(RuntimeError):
    pass


class SignerClient:
    def __init__(self, socket_path: str, timeout_ms: int) -> None:
        self._socket_path = socket_path
        self._timeout = timeout_ms / 1000.0
        # One request at a time. The signer is not a bottleneck at door-opening
        # rates, and serialising keeps the connection handling trivial.
        self._lock = asyncio.Lock()

    @classmethod
    def from_settings(cls, settings: Settings) -> SignerClient:
        return cls(settings.signer_socket, settings.signer_timeout_ms)

    async def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        async with self._lock:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_unix_connection(self._socket_path), self._timeout
                )
            except (TimeoutError, OSError) as exc:
                raise SignerUnavailable(str(exc)) from exc

            try:
                writer.write(encode_request(payload))
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), self._timeout)
            except (TimeoutError, OSError) as exc:
                raise SignerUnavailable(str(exc)) from exc
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

        if not line:
            raise SignerUnavailable("signer closed the connection")
        return decode_line(line)

    async def public_key(self) -> tuple[bytes, str]:
        response = await self._request({"op": "public_key"})
        if not response.get("ok"):
            raise SignerRefused(str(response.get("error")))
        return base64.b64decode(response["public_key"]), response["key_id"]

    async def sign_command(self, command: dict[str, Any]) -> tuple[bytes, str]:
        response = await self._request({"op": "sign", "payload": command})
        if not response.get("ok"):
            raise SignerRefused(str(response.get("error")))
        return base64.b64decode(response["signature"]), response["key_id"]
