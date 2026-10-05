"""Honeypot add-on: fake network services that report every touch to Home Assistant."""

import asyncio
import logging
import os
import signal
import time
from pathlib import Path

import aiohttp
from aiohttp import web

import config
import enrich
import persona
import ui
from enrich import Enricher
from netns import OwnIP
from events import EventStore
from notifier import Notifier
from services import ftp, http, ssh, telnet, tripwire

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("honeypot")

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
# With host_network, the Supervisor's ingress proxy reaches the add-on through
# the hassio bridge gateway. Binding the UI there keeps it off the LAN entirely.
HASSIO_GATEWAY = "172.30.32.1"


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

    own = None
    if cfg["own_ip"]:
        own = OwnIP(who["mac"], who["hostname"], parent=cfg["own_ip_interface"],
                    address=cfg["own_ip_address"], gateway=cfg["own_ip_gateway"])
        try:
            ip = await own.start()
            status["own_ip"] = f"{ip} · MAC {who['mac']} · {who['hostname']}"
            enrich.socket_factory = own.socket
            store.arp_paths.insert(0, own.arp_path)
        except Exception as e:
            log.error("own_ip failed, falling back to HA's IP: %s", e)
            status["own_ip"] = f"failed, using HA's IP: {e}"
            await own.stop()
            own = None

    async def launch(name: str, ports: list[int], starter) -> None:
        """Start a service on the first port that binds; later ports are fallbacks."""
        ports = [p for p in ports if p]
        if not ports:
            status[name] = "disabled"
            return
        errors = []
        for port in ports:
            try:
                servers.append(await starter(port, **({"sock": own.listen_socket(port)} if own else {})))
            except OSError as e:
                errors.append(f"{port}: {e.strerror or e}")
                log.warning("%s honeypot could not bind port %s: %s", name, port, e)
                continue
            status[name] = f"listening on {port}" + (f" (fallback; {', '.join(errors)})" if errors else "")
            log.info("%s honeypot listening on port %s", name, port)
            return
        status[name] = "failed: " + ", ".join(errors)
        log.error("%s honeypot disabled, no port available", name)

    # Port 22 is the real bait, but on HA's own IP it is usually taken by the
    # SSH add-on, so fall back to 2222 there.
    await launch("ssh", [cfg["ssh_port"], cfg["ssh_fallback_port"]],
                 lambda port, **kw: ssh.start(port, report, DATA_DIR / "ssh_host_ed25519_key",
                                              version=who["ssh_banner"], **kw))
    await launch("telnet", [cfg["telnet_port"]],
                 lambda port, **kw: telnet.start(port, report, who["hostname"], who["telnet_banner"], **kw))
    await launch("ftp", [cfg["ftp_port"]],
                 lambda port, **kw: ftp.start(port, report, who["ftp_banner"], **kw))
    await launch("http", [cfg["http_port"]],
                 lambda port, **kw: http.start(port, report, who["http_title"], who["http_server"], **kw))
    for port in cfg["tripwire_ports"]:
        await launch(f"tcp/{port}", [port], lambda p, **kw: tripwire.start(p, report, **kw))

    runner = web.AppRunner(ui.make_app(store, notifier, status, enricher, alerts), access_log=None)
    await runner.setup()
    ui_host = "0.0.0.0"
    if os.getenv("SUPERVISOR_TOKEN"):
        try:
            await web.TCPSite(runner, HASSIO_GATEWAY, cfg["ui_port"]).start()
            ui_host = HASSIO_GATEWAY
        except OSError as e:
            log.warning("Could not bind UI to %s (%s); binding all interfaces, ingress-only", HASSIO_GATEWAY, e)
    if ui_host == "0.0.0.0":
        await web.TCPSite(runner, ui_host, cfg["ui_port"]).start()
    log.info("UI on %s:%s, alerts to %s (cooldown %ss)", ui_host, cfg["ui_port"], notifier.url, cfg["notify_cooldown"])

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    log.info("Shutting down")
    if own:
        await own.stop()  # releases the DHCP lease and removes the interface


if __name__ == "__main__":
    asyncio.run(main())
