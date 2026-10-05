"""Tests for device identification: MAC vendor, DNS/mDNS/NetBIOS parsing, HA matching."""

import asyncio
import struct

import enrich
from notifier import format_alert

MANUF = """# comment
00:1B:63\tApple\tApple, Inc.
B8:27:EB\tRaspberr\tRaspberry Pi Foundation
70:B3:D5:7E:D0:00/36\tSmall\tSmall Vendor Ltd
70:B3:D5\tIeeeRegi\tIEEE Registration Authority
"""


def test_mac_vendor_longest_prefix_wins(tmp_path):
    path = tmp_path / "manuf"
    path.write_text(MANUF)
    table = enrich.load_manuf(path)
    assert enrich.mac_vendor("b8:27:eb:12:34:56", table) == "Raspberry Pi Foundation"
    assert enrich.mac_vendor("70:b3:d5:7e:d0:42", table) == "Small Vendor Ltd"
    assert enrich.mac_vendor("70:b3:d5:11:22:33", table) == "IEEE Registration Authority"
    assert enrich.mac_vendor("12:34:56:78:9a:bc", table) is None
    assert enrich.load_manuf(tmp_path / "missing") == {}


def test_randomized_mac():
    assert enrich.is_randomized_mac("da:a1:19:00:00:01")
    assert not enrich.is_randomized_mac("b8:27:eb:12:34:56")


def _encode_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def test_ptr_query_and_reply_with_compression():
    query = enrich.build_ptr_query("192.168.1.50")
    assert _encode_name("50.1.168.192.in-addr.arpa") in query
    # Reply: header, echoed question, one answer whose name points back at the question.
    header = struct.pack(">HHHHHH", 0, 0x8400, 1, 1, 0, 0)
    question = _encode_name("50.1.168.192.in-addr.arpa") + struct.pack(">HH", 12, 1)
    rdata = _encode_name("Jonass-iPhone.local")
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata
    assert enrich.parse_ptr_reply(header + question + answer) == "Jonass-iPhone.local"
    assert enrich.parse_ptr_reply(b"\x00" * 5) is None


def test_nbstat_reply():
    query = enrich.build_nbstat_query()
    assert query[12] == 0x20 and query[13:15] == b"CK"  # '*' encodes as CK
    names = (b"WORKGROUP".ljust(15) + b"\x00" + struct.pack(">H", 0x8400)    # group name
             + b"DESKTOP-ABC".ljust(15) + b"\x00" + struct.pack(">H", 0x0400))
    rdata = bytes([2]) + names
    reply = (struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + query[12:46]
             + struct.pack(">HHIH", 0x21, 1, 0, len(rdata)) + rdata)
    assert enrich.parse_nbstat_reply(reply) == "DESKTOP-ABC"


def test_match_entities():
    states = [
        {"entity_id": "device_tracker.phone", "attributes": {"friendly_name": "Jonas iPhone", "ip": "192.168.1.50"}},
        {"entity_id": "device_tracker.pi", "attributes": {"mac": "B8:27:EB:12:34:56"}},
        {"entity_id": "light.kitchen", "attributes": {"friendly_name": "Kitchen"}},
    ]
    assert enrich.match_entities(states, "192.168.1.50", None) == ["Jonas iPhone"]
    assert enrich.match_entities(states, "10.0.0.1", "b8:27:eb:12:34:56") == ["device_tracker.pi"]
    assert enrich.match_entities(states, "10.0.0.1", None) == []


def test_enricher_combines_and_caches(tmp_path, monkeypatch):
    path = tmp_path / "manuf"
    path.write_text(MANUF)
    calls = []

    async def fake_rdns(ip):
        calls.append(ip)
        return "pi.lan"

    async def none(ip):
        return None

    class FakeHA:
        async def names(self, ip, mac):
            return ["Garage Pi"]

    monkeypatch.setattr(enrich, "reverse_dns", fake_rdns)
    monkeypatch.setattr(enrich, "mdns_name", none)
    monkeypatch.setattr(enrich, "netbios_name", none)
    e = enrich.Enricher(probe_back=False, manuf_path=path, ha=FakeHA())

    async def go():
        a = await e.host("192.168.1.9", "b8:27:eb:12:34:56")
        b = await e.host("192.168.1.9", "b8:27:eb:12:34:56")
        return a, b

    a, b = asyncio.run(go())
    assert a is b and calls == ["192.168.1.9"]
    assert a["vendor"] == "Raspberry Pi Foundation"
    assert a["dns_name"] == "pi.lan" and a["ha_entities"] == ["Garage Pi"]
    assert a["external"] is False and "open_ports" not in a
    assert e.cached()["192.168.1.9"] is a


def test_open_ports_finds_listener():
    async def go():
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        found = await enrich.open_ports("127.0.0.1", ports=[port, 1], timeout=0.5)
        server.close()
        return port, found

    port, found = asyncio.run(go())
    assert found == [port]


def test_format_alert_with_host_details():
    event = {"service": "ssh", "kind": "login", "src_ip": "192.168.1.9",
             "username": "pi", "password": "raspberry", "mac": "b8:27:eb:12:34:56"}
    host = {"ip": "192.168.1.9", "mac": "b8:27:eb:12:34:56", "vendor": "Raspberry Pi Foundation",
            "randomized_mac": False, "external": False, "ha_entities": ["Garage Pi"],
            "dns_name": "pi.lan", "mdns_name": "raspberrypi.local", "open_ports": [22, 80]}
    activity = {"count": 12, "since": 300, "services": ["ssh", "telnet"], "usernames": ["root", "pi"]}
    title, message = format_alert(event, 4, host, activity)
    assert title == "Honeypot: login attempt on ssh from Garage Pi"
    assert message.splitlines() == [
        "192.168.1.9 tried 'pi' / 'raspberry'",
        "Known in HA as: Garage Pi",
        "Hostname: raspberrypi.local, pi.lan",
        "MAC: b8:27:eb:12:34:56 (Raspberry Pi Foundation)",
        "Its open ports: 22 SSH, 80 HTTP",
        "Activity: 12 events since 5 min ago on ssh, telnet · users tried: root, pi",
        "(+4 more from this host since last alert)",
    ]


def test_format_alert_external_and_randomized():
    event = {"service": "http", "kind": "connect", "src_ip": "8.8.8.8", "detail": "GET /"}
    title, message = format_alert(event, 0, {"external": True, "mac": "da:00:00:00:00:01",
                                             "randomized_mac": True})
    assert "OUTSIDE your LAN" in message
    assert "randomized/private MAC" in message


def test_enricher_persists_hosts(tmp_path, monkeypatch):
    async def none(ip):
        return None

    class NoHA:
        async def names(self, ip, mac):
            return []

    for fn in ("reverse_dns", "mdns_name", "netbios_name"):
        monkeypatch.setattr(enrich, fn, none)
    path = tmp_path / "hosts.json"
    e = enrich.Enricher(probe_back=False, manuf_path=tmp_path / "x", ha=NoHA(), path=path)
    asyncio.run(e.host("192.168.1.7", "da:00:00:00:00:01"))
    again = enrich.Enricher(probe_back=False, manuf_path=tmp_path / "x", ha=NoHA(), path=path)
    assert again.cached()["192.168.1.7"]["randomized_mac"] is True
