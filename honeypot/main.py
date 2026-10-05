"""Honeypot add-on: fake network services that report every touch to Home Assistant."""

import asyncio
import logging
import os
import time
from pathlib import Path

import aiohttp
from aiohttp import web

import config
import persona
import ui
from enrich import Enricher
from events import EventStore
from notifier import Notifier
from services import ftp, http, ssh, telnet, tripwire

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("honeypot")

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))


async def panel_path() -> str | None:
    """HA URL of this add-on's ingress panel, so tapping an alert can open it."""
    token = os.getenv("SUPERVISOR_TOKEN")
    if not token:
        return None
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as s:
        for base in ("http://supervisor", "http://172.30.32.2"):
            try:
                async with s.get(f"{base}/addons/self/info",
                                 headers={"Authorization": f"Bearer {token}"}) as r:
                    if r.status == 200:
                        return f"/{(await r.json())['data']['slug']}"
            except (aiohttp.ClientError, asyncio.TimeoutError, KeyError):
                continue
    return None


async def main() -> None:
    cfg = config.load()
    who = persona.load_or_create(DATA_DIR / "persona.json", cfg)
    log.info("Persona: %s", who)
    store = EventStore(DATA_DIR / "events.jsonl")
    alerts = EventStore(DATA_DIR / "alerts.jsonl", maxlen=300)
    enricher = Enricher(probe_back=cfg["probe_back"], path=DATA_DIR / "hosts.json")

    async def describe(event: dict) -> dict:
        ip = event["src_ip"]
        history = [e for e in store.recent(1000) if e.get("src_ip") == ip]
        activity = {
            "count": len(history),
            "since": time.time() - min((e["ts"] for e in history), default=time.time()),
            "services": sorted({e["service"] for e in history}),
            "usernames": list(dict.fromkeys(e["username"] for e in history if e.get("username")))[:8],
        }
        return {"host": await enricher.host(ip, event.get("mac")), "activity": activity}

    panel = await panel_path()
    log.info("Alert tap opens %s", panel or "(panel path unknown)")
    notifier = Notifier(cfg["ha_url"], cfg["webhook_id"], cfg["notify_cooldown"], describe=describe,
                        on_alert=alerts.add, extra={"panel_path": panel or "/"})
    ignore = set(cfg["ignore_ips"])
    pending: set[asyncio.Task] = set()

    def report(service: str, peer, kind: str, **fields) -> None:
        ip, port = (peer[0], peer[1]) if peer else ("?", 0)
        if ip in ignore:
            return
        event = store.add({"service": service, "kind": kind, "src_ip": ip, "src_port": port, **fields})
        log.warning("%s %s from %s:%s %s", service, kind, ip, port,
                    {k: v for k, v in fields.items() if v})
        task = asyncio.create_task(notifier.handle(event))
        pending.add(task)
        task.add_done_callback(pending.discard)

    status: dict[str, str] = {}
    servers = []

    async def launch(name: str, port: int, starter) -> None:
        if not port:
            status[name] = "disabled"
            return
        try:
            servers.append(await starter())
            status[name] = f"listening on {port}"
            log.info("%s honeypot listening on port %s", name, port)
        except OSError as e:
            status[name] = f"failed on {port}: {e.strerror or e}"
            log.error("%s honeypot could not bind port %s: %s", name, port, e)

    await launch("ssh", cfg["ssh_port"],
                 lambda: ssh.start(cfg["ssh_port"], report, DATA_DIR / "ssh_host_ed25519_key",
                                   version=who["ssh_banner"]))
    await launch("telnet", cfg["telnet_port"], lambda: telnet.start(cfg["telnet_port"], report, who["hostname"], who["telnet_banner"]))
    await launch("ftp", cfg["ftp_port"], lambda: ftp.start(cfg["ftp_port"], report, who["ftp_banner"]))
    await launch("http", cfg["http_port"], lambda: http.start(cfg["http_port"], report, who["http_title"], who["http_server"]))
    for port in cfg["tripwire_ports"]:
        await launch(f"tcp/{port}", port, lambda p=port: tripwire.start(p, report))

    runner = web.AppRunner(ui.make_app(store, notifier, status, enricher, alerts), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", cfg["ui_port"]).start()
    log.info("UI on port %s, alerts to %s (cooldown %ss)", cfg["ui_port"], notifier.url, cfg["notify_cooldown"])

    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
