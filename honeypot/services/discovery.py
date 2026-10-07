"""Notice host discovery: ARP sweeps of the network and pings of the honeypot.

Scanners find live hosts before probing ports (nmap -sn, ARP sweeps, ping
sweeps). The honeypot sees every ARP broadcast on the LAN, and a sweep shows
up as one device asking for many different addresses within seconds.
Ordinary devices never do that, so it's reported as a `discovery` event,
usually before the scanner touches any port. A ping of the honeypot is
reported too.

A single ARP request for the honeypot's address is weak evidence: devices
that saw the fake NAS over mDNS re-check it now and then. Those are logged as
`lookup` events (shown in the panel, no alert).

The kernel still answers the ARP requests and pings; this only listens. The
raw sockets are created in the honeypot's namespace before the add-on drops
root and stay usable afterwards.
"""

import asyncio
from collections import deque
import ipaddress
import logging
import socket
import struct
import time

from services.common import Report

log = logging.getLogger(__name__)

ETH_P_ARP = 0x0806
PER_SOURCE_INTERVAL = 60  # seconds between events per source and method
# ARP requests can also be replies-in-waiting to the honeypot's own traffic:
# devices answering its mDNS probes, or hosts it just looked up after an alert.
# Those aren't scans, so they're ignored for a while.
CONTACT_GRACE = 120
SWEEP_WINDOW = 10   # seconds
SWEEP_TARGETS = 8   # distinct addresses asked for within the window = a sweep
MAX_SOURCES = 1024


def parse_arp_request(frame: bytes) -> tuple[str, str, str] | None:
    """(sender MAC, sender IP, target IP) for an Ethernet ARP request, else None."""
    if len(frame) < 42 or frame[12:14] != b"\x08\x06":
        return None
    htype, ptype, hlen, plen, oper = struct.unpack_from(">HHBBH", frame, 14)
    if (htype, ptype, hlen, plen, oper) != (1, 0x0800, 6, 4, 1):
        return None
    sha, spa, tpa = frame[22:28], frame[28:32], frame[38:42]
    return ":".join(f"{b:02x}" for b in sha), socket.inet_ntoa(spa), socket.inet_ntoa(tpa)


def parse_icmp_echo(packet: bytes) -> tuple[str, str] | None:
    """(source IP, destination IP) for an IPv4 ICMP echo request, else None."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if packet[9] != 1 or len(packet) < ihl + 8 or packet[ihl] != 8:
        return None
    return socket.inet_ntoa(packet[12:16]), socket.inet_ntoa(packet[16:20])


class DiscoveryWatcher:
    def __init__(self, report: Report, own_ip, ignore_sources, clock=time.monotonic):
        self._report = report
        self._own_ip = own_ip            # callable: the honeypot's current IP
        self._ignore = ignore_sources    # callable: IPs that may look for us (gateway)
        self._clock = clock
        self._last: dict[tuple[str, str], float] = {}
        self._socks: list[socket.socket] = []
        self._quiet_until = 0.0
        self._contacted: dict[str, float] = {}
        self._asked: dict[str, deque[tuple[float, str]]] = {}

    def quiet(self, seconds: float = CONTACT_GRACE) -> None:
        """Ignore ARP requests for a while, e.g. while mDNS probes get their answers."""
        self._quiet_until = max(self._quiet_until, self._clock() + seconds)

    def note_contact(self, ip: str) -> None:
        """The honeypot itself just sent traffic to ip; its ARP request may be the reply."""
        self._contacted[ip] = self._clock()

    def _seen(self, method: str, src_ip: str, detail: str, mac: str | None = None,
              kind: str = "discovery") -> None:
        if src_ip in ("0.0.0.0", self._own_ip()) or src_ip in self._ignore():
            return
        try:
            if ipaddress.ip_address(src_ip).is_loopback:
                return
        except ValueError:
            return
        key = (method, src_ip)
        now = self._clock()
        if now - self._last.get(key, -PER_SOURCE_INTERVAL) < PER_SOURCE_INTERVAL:
            return
        self._last[key] = now
        fields = {"detail": detail}
        if mac:
            fields["mac"] = mac
        self._report("discovery", (src_ip, 0), kind, **fields)

    def _sweep_count(self, src: str, target: str, now: float) -> int:
        """Distinct addresses src asked for within the sweep window."""
        asked = self._asked.setdefault(src, deque())
        asked.append((now, target))
        while asked and now - asked[0][0] > SWEEP_WINDOW:
            asked.popleft()
        if len(self._asked) > MAX_SOURCES:  # forget the quietest sources
            for ip in [ip for ip, q in self._asked.items() if not q or now - q[-1][0] > SWEEP_WINDOW]:
                del self._asked[ip]
        return len({t for _, t in asked})

    def on_arp(self, frame: bytes) -> None:
        parsed = parse_arp_request(frame)
        if not parsed:
            return
        mac, src, target = parsed
        if src in ("0.0.0.0", target):  # address probes and gratuitous ARP
            return
        now = self._clock()
        count = self._sweep_count(src, target, now)
        if count >= SWEEP_TARGETS:
            self._seen("sweep", src, f"ARP sweep: asked for {count} addresses in {SWEEP_WINDOW} s", mac)
            return
        if target == self._own_ip():
            if now < self._quiet_until or now - self._contacted.get(src, -CONTACT_GRACE) < CONTACT_GRACE:
                return
            self._seen("arp", src, f"ARP: who has {target}?", mac, kind="lookup")

    def on_icmp(self, packet: bytes) -> None:
        parsed = parse_icmp_echo(packet)
        if parsed and parsed[1] == self._own_ip():
            self._seen("ping", parsed[0], "ping")

    @staticmethod
    def make_sockets(iface: str) -> tuple[socket.socket, socket.socket]:
        """Create the raw sockets. Call in the honeypot's namespace, before dropping root."""
        arp = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
        arp.bind((iface, ETH_P_ARP))
        icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        for s in (arp, icmp):
            s.setblocking(False)
        return arp, icmp

    def start(self, arp: socket.socket, icmp: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        for sock, handler in ((arp, self.on_arp), (icmp, self.on_icmp)):
            loop.add_reader(sock.fileno(), self._drain, sock, handler)
            self._socks.append(sock)

    @staticmethod
    def _drain(sock: socket.socket, handler) -> None:
        for _ in range(100):
            try:
                data = sock.recv(2048)
            except (BlockingIOError, InterruptedError):
                return
            except OSError as e:
                log.debug("discovery socket: %s", e)
                return
            try:
                handler(data)
            except Exception as e:  # never let a malformed frame kill the reader
                log.debug("discovery frame: %s", e)

    def stop(self) -> None:
        loop = asyncio.get_running_loop()
        for s in self._socks:
            loop.remove_reader(s.fileno())
            s.close()
        self._socks.clear()
