"""Work out *which device* an intruder IP is: vendor, hostnames, HA entity, open ports.

Every lookup is best-effort with a short timeout. Results are cached per IP so a
burst of events only triggers one round of lookups.
"""

import asyncio
import ipaddress
import json
import logging
import os
import random
import socket
import struct
import time
from pathlib import Path

import aiohttp

log = logging.getLogger(__name__)

MANUF_PATH = Path(__file__).parent / "manuf"

# Ports whose being open says something about what kind of device this is.
PROBE_PORTS = {
    22: "SSH", 80: "HTTP", 139: "NetBIOS", 443: "HTTPS", 445: "SMB (Windows/NAS)",
    548: "AFP (Mac)", 554: "RTSP (camera)", 3389: "RDP (Windows)", 5000: "UPnP/Synology",
    5900: "VNC", 7000: "AirPlay (Apple)", 8008: "Chromecast", 8080: "HTTP-alt",
    9100: "printer", 62078: "iPhone/iPad",
}


# ── MAC vendor ────────────────────────────────────────────────────────────────

def load_manuf(path: Path = MANUF_PATH) -> dict[int, dict[int, str]]:
    """Parse Wireshark's manuf file into {prefix_bits: {prefix_int: vendor}}."""
    table: dict[int, dict[int, str]] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        log.warning("No MAC vendor database at %s; vendors will be unknown", path)
        return table
    for line in lines:
        if not line or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) < 2:
            continue
        prefix, _, bits = cols[0].partition("/")
        hexdigits = prefix.replace(":", "").replace("-", "").replace(".", "")
        try:
            bits_n = int(bits) if bits else len(hexdigits) * 4
            value = int(hexdigits.ljust(12, "0"), 16) >> (48 - bits_n)
        except ValueError:
            continue
        table.setdefault(bits_n, {})[value] = (cols[2] if len(cols) > 2 and cols[2] else cols[1]).strip()
    return table


def mac_vendor(mac: str, table: dict[int, dict[int, str]]) -> str | None:
    try:
        value = int(mac.replace(":", "").replace("-", ""), 16)
    except ValueError:
        return None
    for bits in sorted(table, reverse=True):
        vendor = table[bits].get(value >> (48 - bits))
        if vendor:
            return vendor
    return None


def is_randomized_mac(mac: str) -> bool:
    """Locally administered bit set: phones/laptops use these as privacy MACs."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except ValueError:
        return False


# ── Name lookups ──────────────────────────────────────────────────────────────

class _UDPOnce(asyncio.DatagramProtocol):
    def __init__(self, payload: bytes):
        self.payload = payload
        self.reply: asyncio.Future = asyncio.get_running_loop().create_future()

    def connection_made(self, transport):
        transport.sendto(self.payload)

    def datagram_received(self, data, addr):
        if not self.reply.done():
            self.reply.set_result(data)

    def error_received(self, exc):
        if not self.reply.done():
            self.reply.set_result(None)


async def udp_query(ip: str, port: int, payload: bytes, timeout: float = 1.5) -> bytes | None:
    loop = asyncio.get_running_loop()
    transport, proto = await loop.create_datagram_endpoint(lambda: _UDPOnce(payload), remote_addr=(ip, port))
    try:
        return await asyncio.wait_for(proto.reply, timeout)
    except asyncio.TimeoutError:
        return None
    finally:
        transport.close()


def _read_name(buf: bytes, off: int) -> tuple[str, int]:
    """Decode a DNS name with compression. Returns (name, offset after the name)."""
    labels, end, jumps = [], None, 0
    while True:
        length = buf[off]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | buf[off + 1]
            jumps += 1
            if jumps > 20:
                raise ValueError("DNS name loop")
            continue
        off += 1
        if length == 0:
            break
        labels.append(buf[off:off + length].decode(errors="replace"))
        off += length
    return ".".join(labels), end if end is not None else off


def build_ptr_query(ip: str) -> bytes:
    name = ipaddress.ip_address(ip).reverse_pointer
    question = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0, 1, 0, 0, 0) + question + struct.pack(">HH", 12, 1)


def parse_ptr_reply(buf: bytes) -> str | None:
    try:
        qd, an = struct.unpack(">HH", buf[4:8])
        off = 12
        for _ in range(qd):
            _, off = _read_name(buf, off)
            off += 4
        for _ in range(an):
            _, off = _read_name(buf, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
            off += 10
            if rtype == 12:
                return _read_name(buf, off)[0]
            off += rdlen
    except (IndexError, struct.error, ValueError):
        pass
    return None


async def mdns_name(ip: str) -> str | None:
    """Ask the device itself over mDNS (unicast to port 5353) for its .local name."""
    reply = await udp_query(ip, 5353, build_ptr_query(ip))
    return parse_ptr_reply(reply) if reply else None


def build_nbstat_query() -> bytes:
    raw = b"*".ljust(16, b"\0")
    encoded = bytes(c for b in raw for c in (0x41 + (b >> 4), 0x41 + (b & 0x0F)))
    return (struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0, 1, 0, 0, 0)
            + b"\x20" + encoded + b"\x00" + struct.pack(">HH", 0x21, 1))


def parse_nbstat_reply(buf: bytes) -> str | None:
    """Return the workstation name (suffix 0x00, unique) from a NetBIOS status reply."""
    try:
        _, off = _read_name(buf, 12)
        off += 10  # type, class, ttl, rdlength
        count = buf[off]
        off += 1
        for i in range(count):
            entry = buf[off + i * 18: off + i * 18 + 18]
            name, suffix, flags = entry[:15], entry[15], struct.unpack(">H", entry[16:18])[0]
            if suffix == 0x00 and not flags & 0x8000:
                return name.decode(errors="replace").strip()
    except (IndexError, struct.error, ValueError):
        pass
    return None


async def netbios_name(ip: str) -> str | None:
    reply = await udp_query(ip, 137, build_nbstat_query())
    return parse_nbstat_reply(reply) if reply else None


async def reverse_dns(ip: str) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        name = (await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), 2))[0]
    except (OSError, asyncio.TimeoutError):
        return None
    return None if name == ip else name


# ── Active probe ──────────────────────────────────────────────────────────────

async def _port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    w.close()
    return True


async def open_ports(ip: str, ports=PROBE_PORTS, timeout: float = 1.0) -> list[int]:
    results = await asyncio.gather(*(_port_open(ip, p, timeout) for p in ports))
    return [p for p, ok in zip(ports, results) if ok]


# ── Home Assistant ────────────────────────────────────────────────────────────

class HALookup:
    """Match an IP/MAC against HA entity attributes (router integrations, device trackers)."""

    BASES = ("http://supervisor/core/api", "http://172.30.32.2/core/api")

    def __init__(self, token: str | None = None, ttl: float = 60):
        self._token = token if token is not None else os.getenv("SUPERVISOR_TOKEN")
        self._ttl = ttl
        self._states: list[dict] = []
        self._fetched = 0.0

    async def _load(self) -> list[dict]:
        if not self._token:
            return []
        if time.monotonic() - self._fetched < self._ttl:
            return self._states
        headers = {"Authorization": f"Bearer {self._token}"}
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as s:
            for base in self.BASES:
                try:
                    async with s.get(f"{base}/states", headers=headers) as r:
                        if r.status == 200:
                            self._states, self._fetched = await r.json(), time.monotonic()
                            break
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue
        return self._states

    async def names(self, ip: str, mac: str | None) -> list[str]:
        return match_entities(await self._load(), ip, mac)


def match_entities(states: list[dict], ip: str, mac: str | None) -> list[str]:
    mac = (mac or "").lower()
    names = []
    for s in states:
        a = s.get("attributes") or {}
        ips = {a.get("ip"), a.get("ip_address"), a.get("local_ip")}
        macs = {str(a.get("mac", "")).lower(), str(a.get("mac_address", "")).lower()}
        if ip in ips or (mac and mac in macs):
            name = a.get("friendly_name") or s.get("entity_id")
            if name not in names:
                names.append(name)
    return names


# ── Putting it together ───────────────────────────────────────────────────────

class Enricher:
    def __init__(self, probe_back: bool = True, cache_ttl: float = 600,
                 manuf_path: Path = MANUF_PATH, ha: HALookup | None = None,
                 path: Path | None = None):
        self._probe_back = probe_back
        self._ttl = cache_ttl
        self._manuf = load_manuf(manuf_path)
        self._ha = ha or HALookup()
        self._path = path
        self._cache: dict[str, tuple[float, dict]] = {}
        # Hosts from earlier runs: shown in the UI, but looked up again when seen.
        if path and path.exists():
            try:
                self._cache = {ip: (float("-inf"), info) for ip, info in json.loads(path.read_text()).items()}
            except (OSError, ValueError) as e:
                log.warning("Could not read %s: %s", path, e)

    def _save(self) -> None:
        if not self._path:
            return
        try:
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.cached()))
            tmp.replace(self._path)
        except OSError as e:
            log.error("Could not save host info: %s", e)

    def cached(self) -> dict[str, dict]:
        return {ip: info for ip, (_, info) in self._cache.items()}

    async def host(self, ip: str, mac: str | None) -> dict:
        hit = self._cache.get(ip)
        if hit and time.monotonic() - hit[0] < self._ttl:
            return hit[1]
        info: dict = {"ip": ip, "mac": mac}
        try:
            info["external"] = not ipaddress.ip_address(ip).is_private
        except ValueError:
            info["external"] = False
        if mac:
            info["vendor"] = mac_vendor(mac, self._manuf)
            info["randomized_mac"] = is_randomized_mac(mac)

        async def safe(coro, default=None):
            try:
                return await coro
            except Exception as e:
                log.debug("lookup failed: %s", e)
                return default

        lookups = [safe(reverse_dns(ip)), safe(mdns_name(ip)), safe(netbios_name(ip)),
                   safe(self._ha.names(ip, mac), [])]
        if self._probe_back and not info["external"]:
            lookups.append(safe(open_ports(ip), []))
        results = await asyncio.gather(*lookups)
        info["dns_name"], info["mdns_name"], info["netbios_name"], info["ha_entities"] = results[:4]
        info["open_ports"] = results[4] if len(results) > 4 else None
        info = {k: v for k, v in info.items() if v not in (None, [], "")}
        self._cache[ip] = (time.monotonic(), info)
        self._save()
        return info
