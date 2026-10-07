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


def test_single_arp_is_a_lookup_and_a_sweep_is_discovery():
    events, now = [], [0.0]
    w = DiscoveryWatcher(lambda s, peer, k, **f: events.append((peer[0], k, f["detail"])), lambda: "192.168.1.191",
                         lambda: {"192.168.1.1"}, clock=lambda: now[0])
    w.on_arp(arp_request("192.168.1.83", "192.168.1.191"))       # hourly re-check of a known NAS
    assert events == [("192.168.1.83", "lookup", "ARP: who has 192.168.1.191?")]
    events.clear()
    for i in range(2, 12):                                       # sweep of other addresses
        now[0] += 0.2
        w.on_arp(arp_request("192.168.1.206", f"192.168.1.{i}"))
    assert events == [("192.168.1.206", "discovery", "ARP sweep: asked for 8 addresses in 10 s")]
    events.clear()
    for i in range(20, 30):                                      # slow, normal traffic: no sweep
        now[0] += 5
        w.on_arp(arp_request("192.168.1.50", f"192.168.1.{i}"))
    w.on_arp(arp_request("192.168.1.50", "192.168.1.50"))        # gratuitous ARP
    assert events == []


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


def test_own_traffic_does_not_count_as_a_scan():
    events, now = [], [1000.0]
    w = DiscoveryWatcher(lambda s, peer, k, **f: events.append(peer[0]), lambda: "192.168.1.191",
                         lambda: set(), clock=lambda: now[0])
    w.quiet(120)                                              # mDNS announcement just started
    w.on_arp(arp_request("192.168.1.194", "192.168.1.191"))   # printer answering the probe
    now[0] += 121
    w.note_contact("192.168.1.50")                            # honeypot looked this host up
    w.on_arp(arp_request("192.168.1.50", "192.168.1.191"))
    w.on_icmp(icmp_echo("192.168.1.50", "192.168.1.191"))     # a ping is never a reply: still reported
    w.on_arp(arp_request("192.168.1.194", "192.168.1.191"))   # after the grace period: a real scan
    assert events == ["192.168.1.50", "192.168.1.194"]
