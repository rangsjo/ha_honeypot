"""Shared helpers for the line-based fake services."""

import asyncio
from typing import Protocol

IAC, SB, SE = 255, 250, 240
WILL, WONT, DO, DONT = 251, 252, 253, 254


class Report(Protocol):
    def __call__(self, service: str, peer, kind: str, **fields) -> None: ...


class LineReader:
    """Read CR/LF/CRLF-terminated lines with a timeout and length cap.

    With telnet=True, IAC negotiation sequences are dropped so usernames and
    passwords come through clean.
    """

    def __init__(self, reader: asyncio.StreamReader, timeout: float = 60.0,
                 limit: int = 256, telnet: bool = False):
        self._reader = reader
        self._timeout = timeout
        self._limit = limit
        self._telnet = telnet
        self._after_cr = False

    async def _byte(self) -> int | None:
        data = await asyncio.wait_for(self._reader.read(1), self._timeout)
        return data[0] if data else None

    async def _skip_telnet_command(self) -> int | None:
        """Consume the rest of an IAC sequence. Returns 255 for an escaped IAC IAC."""
        cmd = await self._byte()
        if cmd == IAC:
            return IAC
        if cmd in (WILL, WONT, DO, DONT):
            await self._byte()
        elif cmd == SB:
            prev = None
            while True:
                c = await self._byte()
                if c is None or (prev == IAC and c == SE):
                    break
                prev = c
        return None

    async def readline(self) -> str | None:
        """Return the next line, or None on EOF/timeout before any data."""
        buf = bytearray()
        try:
            while len(buf) < self._limit:
                c = await self._byte()
                if c is None:
                    return buf.decode(errors="replace") if buf else None
                if self._telnet and c == IAC:
                    c = await self._skip_telnet_command()
                    if c is None:
                        continue
                if c == 0:
                    continue
                after_cr, self._after_cr = self._after_cr, c == 13
                if c == 10 and after_cr:
                    continue  # tail of CRLF
                if c in (10, 13):
                    return buf.decode(errors="replace")
                buf.append(c)
        except (asyncio.TimeoutError, ConnectionError):
            return buf.decode(errors="replace") if buf else None
        return buf.decode(errors="replace")


async def close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 2)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
