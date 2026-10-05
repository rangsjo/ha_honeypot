"""Fake FTP server that accepts USER/PASS and always refuses the login."""

import asyncio

from services.common import LineReader, Report, close

BANNER = b"220 (vsFTPd 3.0.5)\r\n"
MAX_COMMANDS = 30


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 report: Report, timeout: float = 60.0, delay: float = 1.0) -> None:
    peer = writer.get_extra_info("peername")
    report("ftp", peer, "connect")
    lines = LineReader(reader, timeout=timeout)
    user = ""
    try:
        writer.write(BANNER)
        await writer.drain()
        for _ in range(MAX_COMMANDS):
            line = await lines.readline()
            if line is None:
                break
            cmd, _, arg = line.strip().partition(" ")
            cmd = cmd.upper()
            if cmd == "USER":
                user = arg
                reply = b"331 Please specify the password.\r\n"
            elif cmd == "PASS":
                report("ftp", peer, "login", username=user, password=arg)
                await asyncio.sleep(delay)
                reply = b"530 Login incorrect.\r\n"
            elif cmd == "QUIT":
                writer.write(b"221 Goodbye.\r\n")
                await writer.drain()
                break
            elif cmd in ("SYST", "FEAT"):
                reply = b"215 UNIX Type: L8\r\n" if cmd == "SYST" else b"211 End\r\n"
            else:
                reply = b"530 Please login with USER and PASS.\r\n"
            writer.write(reply)
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        await close(writer)


async def start(port: int, report: Report, host: str = "0.0.0.0", **kw) -> asyncio.Server:
    return await asyncio.start_server(lambda r, w: handle(r, w, report, **kw), host, port)
