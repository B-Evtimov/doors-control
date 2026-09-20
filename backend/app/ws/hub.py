"""Registry of live controller connections.

Every controller dials out to the server over WSS and keeps the socket open.
Nothing ever dials in to a controller: there is no listening port on the door
side, so there is no door-side attack surface reachable from a network. The
practical consequence is that the controller works behind any NAT, on any
network the owner happens to have, with no port forwarding and no inbound
firewall rule.

Commands are pushed down that socket. The hub matches acknowledgements back
to the request that is waiting for them.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


class ControllerOffline(RuntimeError):
    pass


class CommandTimeout(RuntimeError):
    pass


@dataclass
class ControllerSession:
    controller_id: uuid.UUID
    controller_code: str
    send: Any                       # awaitable callable taking a str
    connected_at: float = field(default_factory=time.time)
    last_pong_at: float = field(default_factory=time.time)
    remote_ip: str | None = None
    firmware_version: str | None = None
    pending: dict[str, asyncio.Future] = field(default_factory=dict)


class ControllerHub:
    def __init__(self) -> None:
        self._sessions: dict[str, ControllerSession] = {}
        self._lock = asyncio.Lock()

    async def register(self, session: ControllerSession) -> None:
        async with self._lock:
            existing = self._sessions.get(session.controller_code)
            if existing is not None:
                # A second connection for the same controller means either a
                # reconnect the server has not noticed yet, or an impostor
                # that also holds the private key. Either way the older socket
                # is dropped: at most one live session per controller.
                for future in existing.pending.values():
                    if not future.done():
                        future.set_exception(ControllerOffline("superseded"))
            self._sessions[session.controller_code] = session

    async def unregister(self, controller_code: str, session: ControllerSession) -> None:
        async with self._lock:
            if self._sessions.get(controller_code) is session:
                del self._sessions[controller_code]
        for future in session.pending.values():
            if not future.done():
                future.set_exception(ControllerOffline("disconnected"))

    def get(self, controller_code: str) -> ControllerSession | None:
        return self._sessions.get(controller_code)

    def is_online(self, controller_code: str) -> bool:
        return controller_code in self._sessions

    @property
    def online_count(self) -> int:
        return len(self._sessions)

    def online_codes(self) -> list[str]:
        return sorted(self._sessions)

    async def send_command(
        self,
        controller_code: str,
        envelope: dict[str, Any],
        timeout: float,  # noqa: ASYNC109 - the caller owns the command lifetime
    ) -> dict[str, Any]:
        session = self._sessions.get(controller_code)
        if session is None:
            raise ControllerOffline(controller_code)

        command_id = envelope["payload"]["command_id"]
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        session.pending[command_id] = future
        try:
            await session.send(json.dumps(envelope, separators=(",", ":")))
            return await asyncio.wait_for(future, timeout)
        except TimeoutError as exc:
            raise CommandTimeout(command_id) from exc
        finally:
            session.pending.pop(command_id, None)

    def resolve(self, session: ControllerSession, message: dict[str, Any]) -> None:
        command_id = str(message.get("command_id", ""))
        future = session.pending.get(command_id)
        if future is not None and not future.done():
            future.set_result(message)


hub = ControllerHub()
