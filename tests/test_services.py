"""End-to-end tests: start each fake service on a free port and talk to it like a client."""

import asyncio
import base64

import aiohttp
import asyncssh
import pytest

from services import ftp, http, ssh, telnet, tripwire
from services.common import LineReader


class Recorder:
    def __init__(self):
        self.events = []

    def __call__(self, service, peer, kind, **fields):
        self.events.append({"service": service, "kind": kind, "src_ip": peer[0], **fields})

    def logins(self):
        return [e for e in self.events if e["kind"] == "login"]


def port_of(server) -> int:
    return server.sockets[0].getsockname()[1]


async def _reader_with(data: bytes) -> asyncio.StreamReader:
    r = asyncio.StreamReader()
    r.feed_data(data)
    r.feed_eof()
    return r


def test_linereader_strips_telnet_negotiation_and_handles_crlf():
    async def go():
        raw = bytes([255, 253, 1, 255, 250, 24, 1, 255, 240]) + b"root\r\n\r\nadmin\r\x00x\n"
        lr = LineReader(await _reader_with(raw), telnet=True)
        return [await lr.readline() for _ in range(5)]

    assert asyncio.run(go()) == ["root", "", "admin", "x", None]


def test_linereader_caps_length():
    async def go():
        lr = LineReader(await _reader_with(b"A" * 1000 + b"\n"), limit=10)
        return await lr.readline()

    assert asyncio.run(go()) == "A" * 10


def test_telnet_captures_credentials():
    rec = Recorder()

    async def go():
        server = await telnet.start(0, rec, host="127.0.0.1", delay=0)
        r, w = await asyncio.open_connection("127.0.0.1", port_of(server))
        await r.readuntil(b"login: ")
        w.write(b"root\r\n")
        await r.readuntil(b"Password: ")
        w.write(b"hunter2\r\n")
        out = await r.readuntil(b"Login incorrect")
        w.close()
        server.close()
        await asyncio.sleep(0.05)
        return out

    assert b"Login incorrect" in asyncio.run(go())
    assert rec.events[0]["kind"] == "connect"
    assert rec.logins() == [{"service": "telnet", "kind": "login", "src_ip": "127.0.0.1",
                             "username": "root", "password": "hunter2"}]


def test_ftp_captures_credentials():
    rec = Recorder()

    async def go():
        server = await ftp.start(0, rec, host="127.0.0.1", delay=0)
        r, w = await asyncio.open_connection("127.0.0.1", port_of(server))
        replies = [await r.readline()]
        for cmd in (b"USER anonymous", b"PASS guest@", b"LIST", b"QUIT"):
            w.write(cmd + b"\r\n")
            replies.append(await r.readline())
        server.close()
        return replies

    replies = asyncio.run(go())
    assert [x[:3] for x in replies] == [b"220", b"331", b"530", b"530", b"221"]
    assert rec.logins()[0]["username"] == "anonymous"
    assert rec.logins()[0]["password"] == "guest@"


def test_tripwire_records_payload():
    rec = Recorder()

    async def go():
        server = await tripwire.start(0, rec, host="127.0.0.1")
        port = port_of(server)
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"\x03\x00\x00\x13")
        await r.read()
        server.close()
        return port

    port = asyncio.run(go())
    assert rec.events[0]["service"] == f"tcp/{port}"
    assert "\\x03" in rec.events[0]["detail"]


def test_http_form_and_basic_auth():
    rec = Recorder()

    async def go():
        runner = await http.start(0, rec, host="127.0.0.1")
        port = runner.addresses[0][1]
        base = f"http://127.0.0.1:{port}"
        async with aiohttp.ClientSession() as s:
            async with s.get(base + "/cgi-bin/luci") as resp:
                server_header = resp.headers["Server"]
                assert "Router Administration" in await resp.text()
            async with s.post(base + "/login", data={"username": "admin", "password": "1234"}) as resp:
                assert "Invalid" in await resp.text()
            hdr = "Basic " + base64.b64encode(b"admin:admin").decode()
            async with s.get(base + "/", headers={"Authorization": hdr}) as resp:
                assert resp.status == 401
        await runner.cleanup()
        return server_header

    assert asyncio.run(go()) == "lighttpd/1.4.59"
    assert rec.events[0]["kind"] == "connect" and "/cgi-bin/luci" in rec.events[0]["detail"]
    assert [(e["username"], e["password"]) for e in rec.logins()] == [("admin", "1234"), ("admin", "admin")]


def test_ssh_captures_password_and_persists_host_key(tmp_path):
    rec = Recorder()
    key_path = tmp_path / "host_key"

    async def go():
        server = await ssh.start(0, rec, key_path, host="127.0.0.1", delay=0)
        port = server.sockets[0].getsockname()[1]
        with pytest.raises(asyncssh.PermissionDenied):
            await asyncssh.connect("127.0.0.1", port, username="pi", password="raspberry",
                                   known_hosts=None, client_keys=None,
                                   preferred_auth="password")
        server.close()

    asyncio.run(go())
    assert key_path.exists()
    assert rec.events[0]["kind"] == "connect"
    assert rec.logins()[0]["username"] == "pi"
    assert rec.logins()[0]["password"] == "raspberry"
    # Same key is reused on restart, so clients don't see a changed host key.
    assert ssh.load_host_key(key_path).get_fingerprint() == asyncssh.read_private_key(str(key_path)).get_fingerprint()
