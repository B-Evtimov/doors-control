"""acs-signer: the only process that holds the command signing key.

It runs in its own container with:
  * no network namespace at all - it cannot reach the internet or the database
  * a single bind mount: the directory holding its Unix socket
  * a read-only root filesystem
  * one environment variable, ACS_SIGNER_PRIVATE_KEY

It answers exactly two questions: "what is your public key" and "sign this
command". It validates the command before signing it, so even a fully
compromised API cannot get a signature for a command that opens a door for an
hour - the ceiling is in this process, not in the caller.

Splitting it out buys one specific thing: an attacker who owns the API
container can make the signer sign unlock commands while they are there, and
gets nothing that outlives their access. An attacker who owns a process that
holds the key can mint commands forever, including for controllers that are
offline today.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import signal
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from signer.protocol import (
    ALG,
    InvalidCommand,
    canonical_bytes,
    decode_line,
    encode_request,
    validate_command,
)

LOG = logging.getLogger("acs.signer")
MAX_LINE_BYTES = 8 * 1024


class SignerService:
    def __init__(self, private_key: Ed25519PrivateKey, key_id: str) -> None:
        self._key = private_key
        self._key_id = key_id
        self._public = private_key.public_key().public_bytes_raw()

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self._public).decode("ascii")

    def handle(self, request: dict) -> dict:
        op = request.get("op")

        if op == "public_key":
            return {"ok": True, "public_key": self.public_key_b64,
                    "key_id": self._key_id, "alg": ALG}

        if op == "sign":
            payload = request.get("payload")
            if not isinstance(payload, dict):
                return {"ok": False, "error": "payload must be an object"}
            try:
                validate_command(payload)
            except InvalidCommand as exc:
                LOG.warning("refused to sign: %s", exc)
                return {"ok": False, "error": f"refused: {exc}"}
            signature = self._key.sign(canonical_bytes(payload))
            return {
                "ok": True,
                "signature": base64.b64encode(signature).decode("ascii"),
                "key_id": self._key_id,
                "alg": ALG,
            }

        return {"ok": False, "error": "unknown op"}


async def _serve_client(
    service: SignerService,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    try:
        while True:
            line = await reader.readline()
            if not line:
                return
            if len(line) > MAX_LINE_BYTES:
                writer.write(encode_request({"ok": False, "error": "request too large"}))
                await writer.drain()
                return
            try:
                request = decode_line(line)
            except Exception:
                writer.write(encode_request({"ok": False, "error": "malformed request"}))
                await writer.drain()
                return
            writer.write(encode_request(service.handle(request)))
            await writer.drain()
    except (ConnectionResetError, asyncio.IncompleteReadError):
        return
    finally:
        writer.close()


async def run(socket_path: str, private_key_b64: str, key_id: str) -> None:
    raw = base64.b64decode(private_key_b64, validate=True)
    if len(raw) != 32:
        raise SystemExit("ACS_SIGNER_PRIVATE_KEY must decode to exactly 32 bytes")
    service = SignerService(Ed25519PrivateKey.from_private_bytes(raw), key_id)

    path = Path(socket_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()

    server = await asyncio.start_unix_server(
        lambda r, w: _serve_client(service, r, w), path=str(path)
    )
    # Group readable and writable, nothing for the world. The API container
    # shares the group; nothing else on the host does.
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)

    LOG.info("signer listening on %s, key_id=%s", path, key_id)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover - not all platforms
            pass

    async with server:
        await stop.wait()

    path.unlink(missing_ok=True)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    socket_path = os.environ.get("ACS_SIGNER_SOCKET")
    private_key = os.environ.get("ACS_SIGNER_PRIVATE_KEY")
    key_id = os.environ.get("ACS_SIGNER_KEY_ID", "signer-1")
    if not socket_path or not private_key:
        sys.exit("ACS_SIGNER_SOCKET and ACS_SIGNER_PRIVATE_KEY are required")
    asyncio.run(run(socket_path, private_key, key_id))


if __name__ == "__main__":
    main()
