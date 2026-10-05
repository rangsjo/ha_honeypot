"""Announce the fake NAS over mDNS/Bonjour (own-IP mode only).

With the persona's hostname and its open services (SMB, SSH, web) announced,
the honeypot shows up in Finder, file managers and network browsers, the
same way a real NAS does. That catches curious people who would never run a
port scanner.

The Zeroconf instance is created inside the honeypot's network namespace, so
its sockets (and the announcements) only exist on the honeypot's own IP.
"""

import logging
import socket

from zeroconf import IPVersion, ServiceInfo, Zeroconf

log = logging.getLogger(__name__)

SERVICE_TYPES = {
    "smb": "_smb._tcp.local.",
    "ssh": "_ssh._tcp.local.",
    "http": "_http._tcp.local.",
}


def service_infos(hostname: str, ip: str, ports: dict[str, int]) -> list[ServiceInfo]:
    """ServiceInfo records for every listening service we know how to announce."""
    infos = []
    for name, port in ports.items():
        stype = SERVICE_TYPES.get(name)
        if not stype or not port:
            continue
        infos.append(ServiceInfo(
            stype,
            f"{hostname}.{stype}",
            addresses=[socket.inet_aton(ip)],
            port=port,
            server=f"{hostname}.local.",
            properties={"path": "/"} if name == "http" else {},
        ))
    return infos


class Announcer:
    def __init__(self, run_in_netns, hostname: str):
        self._run = run_in_netns  # runs a callable in the honeypot's namespace thread
        self._hostname = hostname
        self._zc: Zeroconf | None = None
        self._infos: list[ServiceInfo] = []

    def start(self, ip: str, ports: dict[str, int]) -> list[str]:
        def create():
            return Zeroconf(interfaces=[ip], ip_version=IPVersion.V4Only)

        self._zc = self._run(create)
        self._infos = service_infos(self._hostname, ip, ports)
        for info in self._infos:
            self._zc.register_service(info, allow_name_change=True)
        names = [i.type.split(".")[0].lstrip("_") for i in self._infos]
        log.info("Announcing %s.local over mDNS: %s", self._hostname, ", ".join(names))
        return names

    def update_ip(self, ip: str) -> None:
        if not self._zc:
            return
        for info in self._infos:
            info.addresses = [socket.inet_aton(ip)]
            self._zc.update_service(info)

    def stop(self) -> None:
        if self._zc:
            self._zc.unregister_all_services()
            self._zc.close()
            self._zc = None
