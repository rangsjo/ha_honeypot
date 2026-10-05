import socket
import struct

from notifier import format_alert
from services.discovery import DiscoveryWatcher, parse_arp_request, parse_icmp_echo


def arp_request(sender_ip, target_ip, sender_mac=b"\x30\xf6\xef\x4c\x95\x0f"):
    eth = b"\xff" * 6 + sender_mac + b"\x08\x06"
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + sender_mac + socket.inet_aton(sender_ip) \
        + b"\x00" * 6 + socket.inet_aton(target_ip)
    return eth + arp


def icmp_echo(src, dst, type_=8):
    ip = bytes([0x45, 0]) + struct.pack(">H", 28) + b"\x00" * 4 + bytes([64, 1]) + b"\x00\x00" \
        + socket.inet_aton(src) + socket.inet_aton(dst)
    return ip + bytes([type_, 0]) + b"\x00" * 6


def test_parsers():
    assert parse_arp_request(arp_request("192.168.1.206", "192.168.1.191")) == \
        ("30:f6:ef:4c:95:0f", "192.168.1.206", "192.168.1.191")
    reply = bytearray(arp_request("192.168.1.206", "192.168.1.191"))
    reply[21] = 2  # ARP reply, not a request
    assert parse_arp_request(bytes(reply)) is None
    assert parse_icmp_echo(icmp_echo("192.168.1.206", "192.168.1.191")) == ("192.168.1.206", "192.168.1.191")
    assert parse_icmp_echo(icmp_echo("192.168.1.206", "192.168.1.191", type_=0)) is None
    assert parse_arp_request(b"short") is None and parse_icmp_echo(b"\x45") is None


def test_watcher_filters_and_throttles():
    events, now = [], [0.0]
    w = DiscoveryWatcher(lambda s, peer, k, **f: events.append((peer[0], f)), lambda: "192.168.1.191",
                         lambda: {"192.168.1.1"}, clock=lambda: now[0])
    w.on_arp(arp_request("192.168.1.206", "192.168.1.191"))
    w.on_arp(arp_request("192.168.1.206", "192.168.1.191"))      # throttled
    w.on_arp(arp_request("192.168.1.1", "192.168.1.191"))        # gateway
    w.on_arp(arp_request("0.0.0.0", "192.168.1.191"))            # ARP probe
    w.on_arp(arp_request("192.168.1.206", "192.168.1.50"))       # not for us
    w.on_icmp(icmp_echo("192.168.1.206", "192.168.1.191"))       # other method: separate throttle
    now[0] = 61
    w.on_arp(arp_request("192.168.1.206", "192.168.1.191"))
    assert [(ip, f["detail"]) for ip, f in events] == [
        ("192.168.1.206", "ARP: who has 192.168.1.191?"), ("192.168.1.206", "ping"),
        ("192.168.1.206", "ARP: who has 192.168.1.191?")]
    assert events[0][1]["mac"] == "30:f6:ef:4c:95:0f"


def test_discovery_alert_text():
    title, msg = format_alert({"service": "discovery", "kind": "discovery", "src_ip": "192.168.1.206",
                               "detail": "ping"}, 0, {"dns_name": "HP-ENVY16.lan"})
    assert title == "Honeypot: network scan from HP-ENVY16.lan"
    assert msg.splitlines()[0] == "192.168.1.206 looked for the honeypot (ping)"
