"""Fake MQTT broker: reads CONNECT, records client id and credentials, refuses.

On a Home Assistant network MQTT is an obvious target: whoever controls the
broker controls the devices. Supports MQTT 3.1, 3.1.1 and 5.
"""

import asyncio
import struct

from services.common import Report, close, serve

MAX_PACKET = 64 * 1024
CONNACK_V3_NOT_AUTHORIZED = b"\x20\x02\x00\x05"
CONNACK_V5_NOT_AUTHORIZED = b"\x20\x03\x00\x87\x00"


class MalformedPacket(ValueError):
    pass


def _varint(buf: bytes, off: int) -> tuple[int, int]:
    value, shift = 0, 0
    for _ in range(4):
        if off >= len(buf):
            raise MalformedPacket("truncated varint")
        b = buf[off]
        off += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, off
        shift += 7
    raise MalformedPacket("varint too long")


def _string(buf: bytes, off: int) -> tuple[bytes, int]:
    if off + 2 > len(buf):
        raise MalformedPacket("truncated length")
    (n,) = struct.unpack_from(">H", buf, off)
    off += 2
    if off + n > len(buf):
        raise MalformedPacket("truncated string")
    return buf[off:off + n], off + n


def parse_connect(body: bytes) -> dict:
    """Parse the variable header + payload of a CONNECT packet."""
    proto, off = _string(body, 0)
    if off + 4 > len(body):
        raise MalformedPacket("truncated header")
    level, flags = body[off], body[off + 1]
    off += 4  # level, flags, keep-alive
    if level == 5:
        n, off = _varint(body, off)
        off += n  # connect properties
    client_id, off = _string(body, off)
    if flags & 0x04:  # will
        if level == 5:
            n, off = _varint(body, off)
            off += n
        _, off = _string(body, off)
        _, off = _string(body, off)
    username = password = None
    if flags & 0x80:
        username, off = _string(body, off)
    if flags & 0x40:
        password, off = _string(body, off)

    def text(b):
        return None if b is None else b.decode("utf-8", errors="replace")
    return {"protocol": text(proto), "level": level, "client_id": text(client_id),
            "username": text(username), "password": text(password)}


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 report: Report, timeout: float = 30.0) -> None:
    peer = writer.get_extra_info("peername")
    report("mqtt", peer, "connect")
    try:
        first = await asyncio.wait_for(reader.readexactly(1), timeout)
        if first[0] >> 4 != 1:  # not CONNECT
            return
        length_bytes = b""
        for _ in range(4):
            length_bytes += await asyncio.wait_for(reader.readexactly(1), timeout)
            if not length_bytes[-1] & 0x80:
                break
        length, _ = _varint(length_bytes, 0)
        if length > MAX_PACKET:
            return
        body = await asyncio.wait_for(reader.readexactly(length), timeout)
        info = parse_connect(body)
        detail = f"MQTT {info['level']}, client id {info['client_id']!r}"
        if info["username"] is not None or info["password"] is not None:
            report("mqtt", peer, "login", username=info["username"] or "",
                   password=info["password"] or "", detail=detail)
        else:
            report("mqtt", peer, "login", username="", password="", detail=detail + ", no credentials")
        writer.write(CONNACK_V5_NOT_AUTHORIZED if info["level"] == 5 else CONNACK_V3_NOT_AUTHORIZED)
        await writer.drain()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, MalformedPacket):
        pass
    finally:
        await close(writer)


async def start(port: int, report: Report, host: str = "0.0.0.0", sock=None, **kw) -> asyncio.Server:
    return await serve(lambda r, w: handle(r, w, report, **kw), host, port, sock)
