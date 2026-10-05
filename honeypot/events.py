"""Event log: in-memory ring buffer for the UI, mirrored to a JSONL file in /data."""

import json
import logging
import time
from collections import deque
from pathlib import Path

log = logging.getLogger(__name__)


def arp_lookup(ip: str, arp_path: Path = Path("/proc/net/arp")) -> str | None:
    """MAC address for a LAN peer from the kernel ARP table (needs host_network)."""
    try:
        lines = arp_path.read_text().splitlines()[1:]
    except OSError:
        return None
    for line in lines:
        cols = line.split()
        if len(cols) >= 4 and cols[0] == ip and cols[3] != "00:00:00:00:00:00":
            return cols[3]
    return None


class EventStore:
    def __init__(self, path: Path | None, maxlen: int = 1000, max_bytes: int = 5_000_000,
                 arp_path: Path = Path("/proc/net/arp")):
        # Checked in order; with own_ip the honeypot namespace's table goes first.
        self._path = path
        self._max_bytes = max_bytes
        self.arp_paths = [arp_path]
        self._events: deque[dict] = deque(maxlen=maxlen)
        self._load()

    def _load(self) -> None:
        if not self._path or not self._path.exists():
            return
        for line in self._path.read_text().splitlines()[-self._events.maxlen:]:
            try:
                self._events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    def add(self, event: dict) -> dict:
        event = {"ts": time.time(), **event}
        if "mac" not in event:
            ip = event.get("src_ip", "")
            event["mac"] = next(filter(None, (arp_lookup(ip, p) for p in self.arp_paths)), None)
        self._events.append(event)
        if self._path:
            try:
                if self._path.exists() and self._path.stat().st_size > self._max_bytes:
                    self._path.replace(self._path.with_suffix(".jsonl.1"))
                with self._path.open("a") as f:
                    f.write(json.dumps(event) + "\n")
            except OSError as e:
                log.error("Could not write event log: %s", e)
        return event

    def history(self) -> list[dict]:
        """Every event still in the log file (falls back to memory without a file)."""
        if not self._path or not self._path.exists():
            return list(self._events)
        out = []
        for line in self._path.read_text().splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def recent(self, limit: int = 200) -> list[dict]:
        return list(self._events)[-limit:][::-1]
