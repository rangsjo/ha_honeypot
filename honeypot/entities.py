"""HA entities kept up to date by the add-on (through the REST API, no MQTT needed).

States set this way are not stored by HA across its restarts, so they are
republished whenever the add-on (re)connects to HA and once a minute.
"""

import asyncio
import logging
import time

from ha_api import HAClient
from notifier import best_name

log = logging.getLogger(__name__)

INTRUSION = "binary_sensor.honeypot_intrusion"
LAST = "sensor.honeypot_last_intruder"
TODAY = "sensor.honeypot_events_today"


class Entities:
    def __init__(self, ha: HAClient, hold: float = 300, clock=time.time):
        self._ha = ha
        self._hold = hold          # seconds the intrusion sensor stays on after the last event
        self._clock = clock
        self._last_event = 0.0
        self._day = self._today()
        self._count = 0
        self._last: tuple[str, dict] = ("none", {})
        self._last_ts = 0.0

    def _today(self) -> str:
        return time.strftime("%Y-%m-%d", time.localtime(self._clock()))

    def states(self) -> dict[str, tuple[str, dict]]:
        if self._today() != self._day:
            self._day, self._count = self._today(), 0
        active = self._clock() - self._last_event < self._hold
        return {
            INTRUSION: ("on" if active else "off", {
                "friendly_name": "Honeypot intrusion", "device_class": "safety", "icon": "mdi:bee"}),
            TODAY: (str(self._count), {
                "friendly_name": "Honeypot events today", "unit_of_measurement": "events",
                "state_class": "total_increasing", "icon": "mdi:counter"}),
            LAST: (self._last[0], {
                "friendly_name": "Honeypot last intruder", "icon": "mdi:account-alert", **self._last[1]}),
        }

    async def publish(self, only: set[str] | None = None) -> None:
        if not self._ha.available:
            return
        for entity_id, (state, attrs) in self.states().items():
            if only is None or entity_id in only:
                try:
                    await self._ha.set_state(entity_id, state, attrs)
                except Exception as e:
                    log.debug("Could not update %s: %s", entity_id, e)
                    return

    def event(self, event: dict) -> None:
        """Any connection or login: count it and switch the intrusion sensor on."""
        self.states()  # roll the day over first
        self._count += 1
        self._last_event = self._clock()

    def alert(self, payload: dict) -> None:
        """An alert carries the identified device, so it updates the last intruder.

        Alerts finish their device lookups in parallel, so an older one can
        arrive later; only a newer event replaces the current state.
        """
        ts = payload.get("ts", self._clock())
        if ts < self._last_ts:
            return
        self._last_ts = ts
        host = payload.get("host") or {}
        name = best_name(host) or payload.get("src_ip") or "unknown"
        self._last = (str(name)[:250], {
            "ip": payload.get("src_ip"), "mac": host.get("mac") or payload.get("mac"),
            "vendor": host.get("vendor"), "service": payload.get("service"), "kind": payload.get("kind"),
            "username": payload.get("username"), "password": payload.get("password"),
            "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(payload.get("ts", self._clock()))),
            "message": payload.get("message"),
        })

    async def run(self) -> None:
        """Republish every minute; that also turns the intrusion sensor back off."""
        while True:
            await self.publish()
            await asyncio.sleep(60)
