"""SMB tripwire: logs the connection and the SMB dialects the client offers.

File shares are the classic way ransomware and worms spread inside a network.
This reads the client's NEGOTIATE request, records which SMB versions it
speaks (a hint at what kind of client it is), and closes the connection.
"""

import asyncio
import struct

from services.common import Report, close, serve

MAX_PACKET = 64 * 1024
SMB2_DIALECTS = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1",
                 0x02FF: "2.???"}


def parse_negotiate(msg: bytes) -> str | None:
    """Describe an SMB1 or SMB2 NEGOTIATE request, or None if it isn't one."""
    if msg[:4] == b"\xffSMB" and len(msg) > 35 and msg[4] == 0x72:
        # SMB1: 32-byte header, word count (1), byte count (2), then 0x02 + dialect\0 ...
        wc = msg[32]
        off = 33 + wc * 2 + 2
        dialects = [d.decode("ascii", errors="replace") for d in msg[off:].split(b"\x00")
                    if d.startswith(b"\x02")]
        return "SMB1 negotiate: " + ", ".join(d[1:] for d in dialects)
    if msg[:4] == b"\xfeSMB" and len(msg) >= 64 + 36:
        (command,) = struct.unpack_from("<H", msg, 12)
        if command != 0:
            return None
        (count,) = struct.unpack_from("<H", msg, 64 + 2)
        count = min(count, 16)
        offs = 64 + 36
        codes = [struct.unpack_from("<H", msg, offs + 2 * i)[0] for i in range(count)
                 if offs + 2 * i + 2 <= len(msg)]
        return "SMB2 negotiate: " + ", ".join(SMB2_DIALECTS.get(c, hex(c)) for c in codes)
    return None


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 report: Report, timeout: float = 10.0) -> None:
    peer = writer.get_extra_info("peername")
    detail = "no SMB request"
    try:
        header = await asyncio.wait_for(reader.readexactly(4), timeout)
        if header[0] == 0:  # NetBIOS session message
            length = int.from_bytes(header[1:], "big")
            if length <= MAX_PACKET:
                msg = await asyncio.wait_for(reader.readexactly(length), timeout)
                detail = parse_negotiate(msg) or f"SMB message {msg[:4]!r}"
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        pass
    report("smb", peer, "connect", detail=detail)
    await close(writer)


async def start(port: int, report: Report, host: str = "0.0.0.0", sock=None, **kw) -> asyncio.Server:
    return await serve(lambda r, w: handle(r, w, report, **kw), host, port, sock)
