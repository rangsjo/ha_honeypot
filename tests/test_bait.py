"""MQTT and SMB bait services: parsers and end-to-end clients."""

import asyncio
import struct

from services import mqtt, smb


def _mqtt_str(s: bytes) -> bytes:
    return struct.pack(">H", len(s)) + s


def _varint(n: int) -> bytes:
    out = b""
    while True:
        b, n = n & 0x7F, n >> 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def connect_packet(level=4, client=b"sensor-1", user=b"admin", password=b"secret", will=False) -> bytes:
    flags = (0x80 if user is not None else 0) | (0x40 if password is not None else 0) | (0x04 if will else 0)
    body = _mqtt_str(b"MQTT") + bytes([level, flags]) + b"\x00\x3c"
    if level == 5:
        body += _varint(0)
    body += _mqtt_str(client)
    if will:
        body += (_varint(0) if level == 5 else b"") + _mqtt_str(b"t") + _mqtt_str(b"m")
    if user is not None:
        body += _mqtt_str(user)
    if password is not None:
        body += _mqtt_str(password)
    return b"\x10" + _varint(len(body)) + body


def test_parse_connect_v311_and_v5_with_will():
    info = mqtt.parse_connect(connect_packet()[2:])
    assert (info["client_id"], info["username"], info["password"]) == ("sensor-1", "admin", "secret")
    info = mqtt.parse_connect(connect_packet(level=5, will=True, user=b"u", password=None)[2:])
    assert info["level"] == 5 and info["username"] == "u" and info["password"] is None


def test_parse_connect_rejects_truncated():
    try:
        mqtt.parse_connect(connect_packet()[2:-3])
    except mqtt.MalformedPacket:
        return
    raise AssertionError("expected MalformedPacket")


class Recorder(list):
    def __call__(self, service, peer, kind, **fields):
        self.append({"service": service, "kind": kind, **fields})


def test_mqtt_end_to_end_refuses_with_not_authorized():
    rec = Recorder()

    async def go():
        server = await mqtt.start(0, rec, host="127.0.0.1")
        r, w = await asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1])
        w.write(connect_packet(level=5))
        reply = await r.read(10)
        server.close()
        return reply

    assert asyncio.run(go()) == mqtt.CONNACK_V5_NOT_AUTHORIZED
    login = [e for e in rec if e["kind"] == "login"][0]
    assert login["username"] == "admin" and login["password"] == "secret"
    assert "sensor-1" in login["detail"]


def smb2_negotiate(dialects=(0x0202, 0x0311)) -> bytes:
    header = b"\xfeSMB" + struct.pack("<H", 64) + b"\x00" * 6 + struct.pack("<H", 0) + b"\x00" * 50
    body = struct.pack("<HHHHI", 36, len(dialects), 1, 0, 0) + b"\x00" * 16 + b"\x00" * 8
    body += b"".join(struct.pack("<H", d) for d in dialects)
    msg = header + body
    return b"\x00" + len(msg).to_bytes(3, "big") + msg


def test_smb_parsers():
    assert smb.parse_negotiate(smb2_negotiate()[4:]) == "SMB2 negotiate: 2.0.2, 3.1.1"
    smb1 = b"\xffSMB\x72" + b"\x00" * 27 + b"\x00" + b"\x00\x00" + b"\x02NT LM 0.12\x00\x02SMB 2.002\x00"
    assert smb.parse_negotiate(smb1) == "SMB1 negotiate: NT LM 0.12, SMB 2.002"
    assert smb.parse_negotiate(b"garbage") is None


def test_smb_end_to_end():
    rec = Recorder()

    async def go():
        server = await smb.start(0, rec, host="127.0.0.1")
        r, w = await asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1])
        w.write(smb2_negotiate())
        await r.read()
        server.close()

    asyncio.run(go())
    assert rec == [{"service": "smb", "kind": "connect", "detail": "SMB2 negotiate: 2.0.2, 3.1.1"}]
