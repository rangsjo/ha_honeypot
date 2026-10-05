"""IPs that never trigger events: from the add-on options plus the ones ignored
from a notification or the panel (kept in /data/ignored.json)."""

import ipaddress
import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)


class IgnoreList:
    def __init__(self, path: Path | None, static: list[str] | None = None):
        self._path = path
        self.static = set(static or [])
        self.dynamic: set[str] = set()
        if path and path.exists():
            try:
                self.dynamic = set(json.loads(path.read_text()))
            except (OSError, ValueError) as e:
                log.warning("Could not read %s: %s", path, e)

    def __contains__(self, ip: str) -> bool:
        return ip in self.static or ip in self.dynamic

    def _save(self) -> None:
        if self._path:
            self._path.write_text(json.dumps(sorted(self.dynamic)))

    def add(self, ip: str) -> str:
        ip = str(ipaddress.ip_address(ip))
        self.dynamic.add(ip)
        self._save()
        log.info("Ignoring %s from now on", ip)
        return ip

    def remove(self, ip: str) -> None:
        self.dynamic.discard(ip)
        self._save()

    def as_dict(self) -> dict:
        return {"options": sorted(self.static), "ignored": sorted(self.dynamic)}
