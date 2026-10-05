"""Fake Telnet login prompt (typical of cheap routers and IoT cameras)."""

import asyncio

from services.common import LineReader, Report, close, serve

MAX_ATTEMPTS = 3


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 report: Report, hostname: str, banner: str = "", timeout: float = 60.0,
                 delay: float = 1.0) -> None:
    peer = writer.get_extra_info("peername")
    report("telnet", peer, "connect")
    lines = LineReader(reader, timeout=timeout, telnet=True)
    try:
        writer.write(f"\r\n{banner}\r\n".encode() if banner else b"\r\n")
        for _ in range(MAX_ATTEMPTS):
            writer.write(f"{hostname} login: ".encode())
            await writer.drain()
            user = await lines.readline()
            if user is None:
                break
            writer.write(b"Password: ")
            await writer.drain()
            password = await lines.readline()
            report("telnet", peer, "login", username=user, password=password or "")
            if password is None:
                break
            await asyncio.sleep(delay)
            writer.write(b"\r\nLogin incorrect\r\n")
    except ConnectionError:
        pass
    finally:
        await close(writer)


async def start(port: int, report: Report, hostname: str = "nas", banner: str = "",
                host: str = "0.0.0.0", sock=None, **kw) -> asyncio.Server:
    return await serve(lambda r, w: handle(r, w, report, hostname, banner, **kw), host, port, sock)
