"""Honeypot add-on: fake network services that report every touch to Home Assistant."""

import asyncio
import logging
import os
import signal
import time
from pathlib import Path

import aiohttp
from aiohttp import web

import channels
import config
import enrich
import entities as entities_module
import persona
import privileges
import ui
from enrich import Enricher
from entities import Entities
from events import EventStore
from ha_api import HAClient
from ignore import IgnoreList
from mdns import Announcer
import netns
from netns import OwnIP
from notifier import Notifier
from services import ftp, http, mqtt, smb, ssh, telnet, tripwire
from services.discovery import DiscoveryWatcher

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

    pending: set[asyncio.Task] = set()

    def background(coro) -> None:
        task = asyncio.create_task(coro)
        pending.add(task)
        task.add_done_callback(pending.discard)

    ha = HAClient()
    entities = Entities(ha)

    def on_alert(payload: dict) -> None:
        alerts.add(payload)
        entities.alert(payload)
        background(entities.publish({entities_module.LAST}))
        if ha.available:  # automation trigger + logbook entry, independent of phone delivery
            background(ha.fire_event("honeypot_alert", payload))
            if cfg["persistent_notification"]:
                background(channels.persistent_notification(ha, payload))

    panel = await panel_path()
    log.info("Alert tap opens %s", panel or "(panel path unknown)")
    targets = [t for t in cfg["notify_targets"] if t.strip()]
    notifier = Notifier(cfg["ha_url"], cfg["webhook_id"], cfg["notify_cooldown"], describe=describe,
                        on_alert=on_alert, extra={"panel_path": panel or "/"},
                        channels=[channels.notify_channel(ha, t, cfg["critical_alerts"]) for t in targets]
                        if ha.available else [])
    log.info("Alerts go to: %s", ", ".join(
        ([f"notify.{channels.notify_service(t)}" for t in targets] if ha.available else [])
        + ([f"webhook {cfg['webhook_id']}"] if notifier.url else [])) or "nowhere (set notify_targets)")
    ignore = IgnoreList(DATA_DIR / "ignored.json", cfg["ignore_ips"])

    async def on_notification_action(data: dict) -> None:
        ip = channels.parse_ignore_action(data.get("action", ""))
        if ip:
            ignore.add(ip)

    def report(service: str, peer, kind: str, **fields) -> None:
        ip, port = (peer[0], peer[1]) if peer else ("?", 0)
        if ip in ignore:
            return
        event = store.add({"service": service, "kind": kind, "src_ip": ip, "src_port": port, **fields})
        entities.event(event)
        background(entities.publish({entities_module.INTRUSION, entities_module.TODAY}))
        log.warning("%s %s from %s:%s %s", service, kind, ip, port,
                    {k: v for k, v in fields.items() if v})
        background(notifier.handle(event))

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

    listening: dict[str, int] = {}

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
            listening[name] = port
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
    # On HA's own IP these would take ports the Mosquitto or Samba add-ons need.
    for name, module in (("smb", smb), ("mqtt", mqtt)):
        port = cfg[f"{name}_port"]
        if own:
            await launch(name, [port], lambda p, m=module, **kw: m.start(p, report, **kw))
        elif port:
            status[name] = "own IP only"
    for port in cfg["tripwire_ports"]:
        await launch(f"tcp/{port}", [port], lambda p, **kw: tripwire.start(p, report, **kw))

    watcher = None
    if own and cfg["detect_discovery"]:
        watcher = DiscoveryWatcher(report, lambda: own.ip, lambda: {own.gateway_ip})
        try:
            watcher.start(*own.run_in_netns(DiscoveryWatcher.make_sockets, netns.IFACE))
            enrich.contact_hook = watcher.note_contact
            status["discovery"] = "watching ARP and ping"
        except OSError as e:  # needs NET_RAW, created before dropping root
            log.error("Discovery detection unavailable: %s", e)
            status["discovery"] = f"failed: {e.strerror or e}"
            watcher = None

    announcer = None
    if own and cfg["mdns"]:
        announcer = Announcer(own.run_in_netns, who["hostname"])
        if watcher:
            watcher.quiet()  # devices answering the mDNS probes ARP for us
        try:
            names = await asyncio.get_running_loop().run_in_executor(None, announcer.start, own.ip, listening)
            status["mdns"] = f"{who['hostname']}.local: {', '.join(names) or 'no services'}"
        except Exception as e:
            log.error("mDNS announcement failed: %s", e)
            status["mdns"] = f"failed: {e}"
            announcer = None

    runner = web.AppRunner(ui.make_app(store, notifier, status, enricher, alerts, ignore=ignore), access_log=None)
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
    # Everything that needed root is done; the services now face attackers unprivileged.
    status["privileges"] = privileges.drop(DATA_DIR)
    log.info("UI on %s:%s, alerts to %s (cooldown %ss)", ui_host, cfg["ui_port"], notifier.url, cfg["notify_cooldown"])

    if own and not cfg["own_ip_address"]:
        async def follow_dhcp() -> None:
            while True:
                await asyncio.sleep(30)
                if own.refresh_ip():
                    status["own_ip"] = f"{own.ip} · MAC {who['mac']} · {who['hostname']}"
                    if announcer:
                        if watcher:
                            watcher.quiet()
                        announcer.update_ip(own.ip)
        background(follow_dhcp())

    if ha.available:
        background(entities.run())
        background(ha.listen("mobile_app_notification_action", on_notification_action,
                             on_connect=entities.publish))

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    log.info("Shutting down")
    if watcher:
        watcher.stop()
    if announcer:
        announcer.stop()  # goodbye packets, so it disappears from network browsers
    if own:
        await own.stop()  # releases the DHCP lease and removes the interface


if __name__ == "__main__":
    asyncio.run(main())
