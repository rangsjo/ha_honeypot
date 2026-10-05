"""Plain TCP listeners: any connection is suspicious, record the first bytes sent."""

import asyncio

from services.common import Report, close, serve


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 report: Report, timeout: float = 3.0) -> None:
    peer = writer.get_extra_info("peername")
    port = writer.get_extra_info("sockname")[1]
    try:
        data = await asyncio.wait_for(reader.read(512), timeout)
    except (asyncio.TimeoutError, ConnectionError):
        data = b""
    detail = f"sent {data[:64]!r}" if data else "no data"
    report(f"tcp/{port}", peer, "connect", detail=detail)
    await close(writer)


async def start(port: int, report: Report, host: str = "0.0.0.0", sock=None, **kw) -> asyncio.Server:
    return await serve(lambda r, w: handle(r, w, report, **kw), host, port, sock)
