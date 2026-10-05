"""Forward honeypot events to a Home Assistant webhook, rate-limited per source IP.

A port scan touches every service within a second, and a brute-forcer tries
hundreds of passwords. To keep the phone usable, each source IP gets at most one
"connect" alert and one "login" alert per cooldown window; anything held back is
counted and reported in the next alert. Every event is still logged.
"""

import logging
import time
from typing import Awaitable, Callable

import aiohttp

from enrich import PROBE_PORTS

log = logging.getLogger(__name__)

Sender = Callable[[str, dict], Awaitable[None]]
Describer = Callable[[dict], Awaitable[dict]]
AlertSink = Callable[[dict], None]
Channel = Callable[[dict], Awaitable[None]]


def _ago(seconds: float) -> str:
    if seconds < 90:
        return "just now"
    if seconds < 5400:
        return f"{round(seconds / 60)} min ago"
    return f"{seconds / 3600:.1f} h ago"


def best_name(host: dict) -> str | None:
    for key in ("ha_entities", "mdns_name", "netbios_name", "dns_name"):
        value = host.get(key)
        if value:
            return value[0] if isinstance(value, list) else value
    return host.get("vendor")


def format_alert(event: dict, suppressed: int = 0, host: dict | None = None,
                 activity: dict | None = None) -> tuple[str, str]:
    host = host or {}
    service, ip = event["service"], event["src_ip"]
    name = best_name(host)
    if event["kind"] == "discovery":
        title = "Honeypot: network scan"
        lines = [f"{ip} looked for the honeypot ({event.get('detail') or 'discovery'})"]
    elif event["kind"] == "login":
        title = f"Honeypot: login attempt on {service}"
        secret = event.get("password") or event.get("detail") or ""
        lines = [f"{ip} tried {event.get('username', '')!r} / {secret!r}"]
        if event.get("password") and event.get("detail"):
            lines.append(event["detail"])
    else:
        title = f"Honeypot: connection to {service}"
        lines = [f"{ip} connected to {service}" + (f": {event['detail']}" if event.get("detail") else "")]
    if name:
        title += f" from {name}"

    if host.get("external"):
        lines.append("⚠️ Source is OUTSIDE your LAN (check port forwarding)")
    if host.get("ha_entities"):
        lines.append("Known in HA as: " + ", ".join(host["ha_entities"]))
    names = [host[k] for k in ("mdns_name", "netbios_name", "dns_name") if host.get(k)]
    if names:
        lines.append("Hostname: " + ", ".join(dict.fromkeys(names)))
    mac = host.get("mac") or event.get("mac")
    if mac:
        extra = [x for x in (host.get("vendor"),
                             "randomized/private MAC" if host.get("randomized_mac") else None) if x]
        lines.append(f"MAC: {mac}" + (f" ({', '.join(extra)})" if extra else ""))
    if host.get("open_ports"):
        lines.append("Its open ports: " + ", ".join(
            f"{p} {PROBE_PORTS.get(p, '')}".strip() for p in host["open_ports"]))
    if activity and activity.get("count", 0) > 1:
        line = (f"Activity: {activity['count']} events since {_ago(activity['since'])}"
                f" on {', '.join(activity['services'])}")
        if activity.get("usernames"):
            line += " · users tried: " + ", ".join(activity["usernames"])
        lines.append(line)
    if suppressed:
        lines.append(f"(+{suppressed} more from this host since last alert)")
    return title, "\n".join(lines)


async def _post(url: str, payload: dict) -> None:
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
        async with session.post(url, json=payload) as r:
            if r.status >= 300:
                raise RuntimeError(f"HA webhook returned {r.status}")


class Notifier:
    def __init__(self, ha_url: str, webhook_id: str, cooldown: float,
                 send: Sender = _post, clock: Callable[[], float] = time.monotonic,
                 describe: Describer | None = None, on_alert: AlertSink | None = None,
                 extra: dict | None = None, channels: list[Channel] | None = None):
        # The webhook is optional now that alerts can go straight to notify targets.
        self.url = f"{ha_url.rstrip('/')}/api/webhook/{webhook_id}" if webhook_id else None
        self.channels = list(channels or [])
        self._cooldown = cooldown
        self._send = send
        self._clock = clock
        self._describe = describe
        self._on_alert = on_alert
        self.extra = extra or {}  # added to every payload, e.g. panel_path
        self._last_sent: dict[tuple[str, str], float] = {}
        self._suppressed: dict[tuple[str, str], int] = {}

    def _check(self, event: dict) -> tuple[bool, int]:
        key = (event["src_ip"], event["kind"])
        now = self._clock()
        last = self._last_sent.get(key)
        if last is not None and now - last < self._cooldown:
            self._suppressed[key] = self._suppressed.get(key, 0) + 1
            return False, 0
        self._last_sent[key] = now
        return True, self._suppressed.pop(key, 0)

    async def handle(self, event: dict) -> bool:
        ok, suppressed = self._check(event)
        if not ok:
            return False
        context = {}
        if self._describe:
            try:
                context = await self._describe(event)
            except Exception as e:
                log.warning("Could not identify %s: %s", event["src_ip"], e)
        title, message = format_alert(event, suppressed, context.get("host"), context.get("activity"))
        payload = {"title": title, "message": message, "suppressed": suppressed,
                   **event, **context, **self.extra}
        try:
            delivered = await self._deliver(payload)
        except Exception as e:
            self._record(payload, delivered=False)
            log.error("Alert delivery failed: %s", e)
            # Let the next event from this host retry instead of waiting out the cooldown.
            key = (event["src_ip"], event["kind"])
            self._last_sent.pop(key, None)
            self._suppressed[key] = self._suppressed.get(key, 0) + suppressed + 1
            return False
        self._record(payload, delivered=delivered)
        return delivered

    async def _deliver(self, payload: dict) -> bool:
        """Send to the webhook and every channel. Raises only if all of them fail.

        Returns False when nothing is configured, so the alert is kept in the
        panel without retrying.
        """
        senders = ([lambda p: self._send(self.url, p)] if self.url else []) + self.channels
        if not senders:
            log.warning("No notification target configured; alert only shown in the panel")
            return False
        errors = []
        for send in senders:
            try:
                await send(payload)
            except Exception as e:
                errors.append(str(e))
        if len(errors) == len(senders):
            raise RuntimeError("; ".join(errors))
        for e in errors:
            log.warning("One alert channel failed: %s", e)
        return True

    def _record(self, payload: dict, delivered: bool) -> None:
        if self._on_alert:
            try:
                self._on_alert({**payload, "delivered": delivered})
            except Exception as e:
                log.error("Could not save alert: %s", e)

    async def test(self) -> None:
        if not await self._deliver({
            "title": "Honeypot: test alert",
            "message": "If you can read this, honeypot alerts reach your phone.",
            "kind": "test", "service": "test", "src_ip": "", "ts": time.time(), **self.extra,
        }):
            raise RuntimeError("no notification target configured (set notify_targets)")
