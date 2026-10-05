"""Tests for config loading, the event store and notification rate limiting."""

import asyncio
import json

import config
from events import EventStore, arp_lookup
from notifier import Notifier, format_alert

ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.50     0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.51     0x1         0x0         00:00:00:00:00:00     *        eth0
"""


def test_config_options_then_env(tmp_path, monkeypatch):
    opts = tmp_path / "options.json"
    opts.write_text(json.dumps({"ssh_port": 22, "ignore_ips": ["10.0.0.1"]}))
    monkeypatch.setenv("TRIPWIRE_PORTS", "1,2")
    monkeypatch.setenv("WEBHOOK_ID", "x")
    cfg = config.load(opts)
    assert cfg["ssh_port"] == 22
    assert cfg["ignore_ips"] == ["10.0.0.1"]
    assert cfg["tripwire_ports"] == [1, 2]
    assert cfg["webhook_id"] == "x"
    assert cfg["telnet_port"] == 23


def test_arp_lookup(tmp_path):
    arp = tmp_path / "arp"
    arp.write_text(ARP)
    assert arp_lookup("192.168.1.50", arp) == "aa:bb:cc:dd:ee:ff"
    assert arp_lookup("192.168.1.51", arp) is None  # incomplete entry
    assert arp_lookup("192.168.1.99", arp) is None
    assert arp_lookup("192.168.1.50", tmp_path / "missing") is None


def test_event_store_persists_and_rotates(tmp_path):
    path = tmp_path / "events.jsonl"
    store = EventStore(path, max_bytes=200, arp_path=tmp_path / "none")
    for i in range(5):
        store.add({"service": "ssh", "kind": "login", "src_ip": "1.2.3.4", "username": f"u{i}"})
    assert store.recent(2)[0]["username"] == "u4"
    assert (tmp_path / "events.jsonl.1").exists()
    reloaded = EventStore(path)
    assert reloaded.recent(1)[0]["username"] == "u4"


def _event(kind="login", ip="192.168.1.50", **kw):
    return {"service": "ssh", "kind": kind, "src_ip": ip, "mac": None, **kw}


def test_notifier_cooldown_per_ip_and_kind():
    sent = []
    now = [0.0]

    async def send(url, payload):
        sent.append(payload)

    n = Notifier("http://ha:8123/", "hp", cooldown=60, send=send, clock=lambda: now[0])
    assert n.url == "http://ha:8123/api/webhook/hp"

    async def go():
        await n.handle(_event("connect"))
        await n.handle(_event("login", username="root", password="a"))
        for _ in range(3):
            await n.handle(_event("login", username="root", password="b"))  # suppressed
        await n.handle(_event("login", ip="192.168.1.60", username="x", password="y"))  # other host
        now[0] = 61
        await n.handle(_event("login", username="root", password="c"))

    asyncio.run(go())
    assert [p["kind"] for p in sent] == ["connect", "login", "login", "login"]
    assert sent[-1]["suppressed"] == 3
    assert "+3 more" in sent[-1]["message"]


def test_notifier_survives_webhook_failure():
    async def send(url, payload):
        raise ConnectionError("HA down")

    n = Notifier("http://ha:8123", "hp", cooldown=600, send=send)
    assert asyncio.run(n.handle(_event())) is False

    sent = []

    async def recovered(url, payload):
        sent.append(payload)

    n._send = recovered
    assert asyncio.run(n.handle(_event())) is True  # failure did not start the cooldown
    assert sent[0]["suppressed"] == 1


def test_format_alert():
    title, msg = format_alert(_event(username="admin", password="admin", mac="aa:bb"))
    assert title == "Honeypot: login attempt on ssh"
    assert msg == "192.168.1.50 tried 'admin' / 'admin'\nMAC: aa:bb"
    title, msg = format_alert({"service": "tcp/3389", "kind": "connect", "src_ip": "10.0.0.9",
                               "detail": "no data"})
    assert msg == "10.0.0.9 connected to tcp/3389: no data"


def test_notifier_records_alerts_delivered_or_not():
    saved = []
    fail = [True]

    async def send(url, payload):
        if fail[0]:
            raise ConnectionError("HA down")

    async def describe(event):
        return {"host": {"vendor": "Apple, Inc."}, "activity": {"count": 1}}

    n = Notifier("http://ha", "hp", cooldown=600, send=send, describe=describe,
                 on_alert=saved.append, extra={"panel_path": "/local_honeypot"})

    async def go():
        await n.handle(_event(username="a", password="b"))
        fail[0] = False
        await n.handle(_event(username="a", password="c"))

    asyncio.run(go())
    assert [a["delivered"] for a in saved] == [False, True]
    assert saved[1]["panel_path"] == "/local_honeypot"
    assert saved[1]["host"]["vendor"] == "Apple, Inc."
    assert "tried 'a' / 'c'" in saved[1]["message"]
