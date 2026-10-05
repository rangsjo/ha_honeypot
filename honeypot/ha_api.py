"""Talk to Home Assistant Core through the Supervisor proxy (homeassistant_api: true).

With host networking the `supervisor` hostname may not resolve, so the
Supervisor's fixed IP is tried as a fallback. Outside the Supervisor (standalone
Docker), set HA_API_URL (e.g. http://homeassistant.local:8123) and HA_TOKEN
(a long-lived access token) instead.
"""

import asyncio
import logging
import os
from typing import Awaitable, Callable

import aiohttp

log = logging.getLogger(__name__)

BASES = ("http://supervisor/core", "http://172.30.32.2/core")


class HAClient:
    def __init__(self, token: str | None = None, bases=None):
        standalone = os.getenv("HA_API_URL")
        if bases is None:
            bases = [standalone.rstrip("/")] if standalone else BASES
        if token is None:
            token = os.getenv("HA_TOKEN") if standalone else os.getenv("SUPERVISOR_TOKEN")
        self.token = token
        self._bases = list(bases)
        self._base: str | None = None

    @property
    def available(self) -> bool:
        return bool(self.token)

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    async def request(self, method: str, path: str, json=None):
        """Call /api/<path>. Raises on failure; remembers which base works."""
        if not self.token:
            raise RuntimeError("no Supervisor token")
        bases = [self._base] if self._base else self._bases
        last: Exception | None = None
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as s:
            for base in bases:
                try:
                    async with s.request(method, f"{base}/api/{path}", json=json, headers=self._headers()) as r:
                        if r.status >= 400:
                            raise RuntimeError(f"HA API {method} {path}: HTTP {r.status} {(await r.text())[:200]}")
                        self._base = base
                        return await r.json(content_type=None)
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    last = e
                    continue
        self._base = None
        raise RuntimeError(f"HA API unreachable: {last}")

    async def call_service(self, domain: str, service: str, data: dict) -> None:
        await self.request("POST", f"services/{domain}/{service}", data)

    async def fire_event(self, event_type: str, data: dict) -> None:
        await self.request("POST", f"events/{event_type}", data)

    async def set_state(self, entity_id: str, state, attributes: dict) -> None:
        await self.request("POST", f"states/{entity_id}", {"state": state, "attributes": attributes})

    async def states(self) -> list[dict]:
        return await self.request("GET", "states")

    async def listen(self, event_type: str, on_event: Callable[[dict], Awaitable[None]],
                     on_connect: Callable[[], Awaitable[None]] | None = None) -> None:
        """Subscribe to an HA event type over the websocket API, reconnecting forever.

        on_connect runs after every (re)connect, e.g. to republish entity
        states that HA forgets on restart.
        """
        delay = 5
        while True:
            for base in ([self._base] if self._base else self._bases):
                # Supervisor proxy: /core/websocket; HA directly: /api/websocket
                path = "/websocket" if base.endswith("/core") else "/api/websocket"
                url = base.replace("https://", "wss://").replace("http://", "ws://") + path
                try:
                    async with aiohttp.ClientSession() as s, s.ws_connect(url, heartbeat=30) as ws:
                        await ws.receive_json()  # auth_required
                        await ws.send_json({"type": "auth", "access_token": self.token})
                        if (await ws.receive_json()).get("type") != "auth_ok":
                            raise RuntimeError("websocket auth failed")
                        await ws.send_json({"id": 1, "type": "subscribe_events", "event_type": event_type})
                        delay = 5
                        if on_connect:
                            await on_connect()
                        async for msg in ws:
                            if msg.type != aiohttp.WSMsgType.TEXT:
                                break
                            data = msg.json()
                            if data.get("type") == "event":
                                try:
                                    await on_event(data["event"].get("data") or {})
                                except Exception as e:
                                    log.error("Handling %s failed: %s", event_type, e)
                except Exception as e:
                    log.debug("HA websocket %s: %s", url, e)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 300)
