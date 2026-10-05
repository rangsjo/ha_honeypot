"""Give the honeypot its own network identity (the `own_ip` option).

A macvlan interface with its own MAC address is created on HA's Ethernet port
and moved into a private network namespace, where it gets its own IP over DHCP
under the persona's hostname. To the rest of the LAN it is a separate device.

Doing this in a separate namespace, rather than adding an address to HA's own
interface, keeps HA's routing and ARP untouched: the host never learns the
honeypot's IP, so it can't answer for it with HA's MAC.

The namespace is held open by a `sleep` process. If the add-on dies, that
process dies with the container and the kernel deletes the interface.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

log = logging.getLogger(__name__)

IFACE = "honeypot0"
# Both receive failures below have the same usual cause.
RECEIVE_HINT = ("Traffic for the honeypot's own MAC doesn't arrive. In a VM, set the network adapter to "
                "bridged and allow other MACs (VirtualBox: Promiscuous Mode 'Allow All'; Hyper-V: MAC "
                "address spoofing). On Wi-Fi, own IP can't work.")
DHCP_SCRIPT = Path(__file__).parent / "udhcpc.script"


async def _run(*args: str, check: bool = True) -> str:
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    if check and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {err.decode().strip() or proc.returncode}")
    return out.decode()


def parse_default_iface(route_output: str) -> str | None:
    m = re.search(r"^default .*?\bdev (\S+)", route_output, re.M)
    return m.group(1) if m else None


def parse_gateway(route_output: str) -> str | None:
    m = re.search(r"^default via (\d+\.\d+\.\d+\.\d+)", route_output, re.M)
    return m.group(1) if m else None


def parse_ipv4(addr_output: str) -> str | None:
    m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)/", addr_output)
    return m.group(1) if m else None


class OwnIP:
    def __init__(self, mac: str, hostname: str, parent: str = "", address: str = "",
                 gateway: str = "", dhcp_timeout: float = 30):
        self.mac = mac
        self.hostname = hostname
        self.parent = parent
        self.address = address  # static "192.168.1.250/24"; empty = DHCP
        self.gateway = gateway
        self.dhcp_timeout = dhcp_timeout
        self.ip: str | None = None
        self._holder: asyncio.subprocess.Process | None = None
        self._dhcp: asyncio.subprocess.Process | None = None
        self._ns_fd: int | None = None
        self._executor: ThreadPoolExecutor | None = None

    def _ns(self, *args: str) -> tuple[str, ...]:
        return ("nsenter", "-t", str(self._holder.pid), "-n", *args)

    async def start(self) -> str:
        parent = self.parent or parse_default_iface(await _run("ip", "-4", "route", "show", "default"))
        if not parent:
            raise RuntimeError("no default route; set own_ip_interface")
        if Path(f"/sys/class/net/{parent}/wireless").exists():
            raise RuntimeError(f"{parent} is Wi-Fi; own_ip needs HA on Ethernet")

        self._holder = await asyncio.create_subprocess_exec("unshare", "--net", "--", "sleep", "infinity")
        own_ns = os.readlink("/proc/self/ns/net")
        for _ in range(50):
            if self._holder.returncode is not None:
                break  # unshare refused (no SYS_ADMIN)
            try:
                if os.readlink(f"/proc/{self._holder.pid}/ns/net") != own_ns:
                    break
            except OSError:
                pass
            await asyncio.sleep(0.05)
        else:
            raise RuntimeError("could not create network namespace (needs SYS_ADMIN)")
        self._ns_fd = os.open(f"/proc/{self._holder.pid}/ns/net", os.O_RDONLY)
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="netns",
            initializer=os.setns, initargs=(self._ns_fd, os.CLONE_NEWNET))

        await _run("ip", "link", "delete", IFACE, check=False)  # leftover from a crash
        await _run("ip", "link", "add", IFACE, "link", parent, "address", self.mac,
                   "type", "macvlan", "mode", "bridge")
        await _run("ip", "link", "set", IFACE, "netns", str(self._holder.pid))
        await _run(*self._ns("ip", "link", "set", "lo", "up"))
        await _run(*self._ns("ip", "link", "set", IFACE, "up"))

        if self.address:
            await _run(*self._ns("ip", "addr", "add", self.address, "dev", IFACE))
            if self.gateway:
                await _run(*self._ns("ip", "route", "add", "default", "via", self.gateway))
        else:
            self._dhcp = await asyncio.create_subprocess_exec(
                *self._ns("udhcpc", "-f", "-R", "-i", IFACE, "-s", str(DHCP_SCRIPT),
                          "-x", f"hostname:{self.hostname}"),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.dhcp_timeout
        while loop.time() < deadline:
            self.ip = parse_ipv4(await _run(*self._ns("ip", "-4", "-o", "addr", "show", "dev", IFACE)))
            if self.ip:
                await self._check_receive()
                log.info("Own IP %s on %s via %s (MAC %s, hostname %s)",
                         self.ip, IFACE, parent, self.mac, self.hostname)
                return self.ip
            await asyncio.sleep(0.5)
        raise RuntimeError(f"DHCP request sent from {self.mac}, but no reply arrived within "
                           f"{self.dhcp_timeout:.0f}s. {RECEIVE_HINT}")

    async def _check_receive(self) -> None:
        """Make sure unicast frames to our MAC get through (a static address wouldn't notice otherwise).

        Sending anything to the gateway triggers an ARP request; the gateway's
        reply is addressed to the honeypot's MAC, which is exactly what a VM
        without promiscuous mode drops.
        """
        gateway = parse_gateway(await _run(*self._ns("ip", "-4", "route", "show", "default")))
        if not gateway:
            return
        s = self.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(b"", (gateway, 9))
        except OSError:
            pass
        finally:
            s.close()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 3
        while loop.time() < deadline:
            if "lladdr" in await _run(*self._ns("ip", "neigh", "show", gateway, "dev", IFACE)):
                return
            await asyncio.sleep(0.3)
        raise RuntimeError(f"got {self.ip}, but the gateway {gateway} can't be reached from it. {RECEIVE_HINT}")

    @property
    def arp_path(self) -> Path:
        """ARP table of the honeypot's namespace: where intruders' MACs show up."""
        return Path(f"/proc/{self._holder.pid}/net/arp")

    def socket(self, family: int = socket.AF_INET, type: int = socket.SOCK_STREAM) -> socket.socket:
        """An unbound socket inside the honeypot's namespace.

        Used for listening and for the outbound enrichment lookups, so the
        intruder only ever sees traffic from the honeypot's IP, never from HA's.
        """
        return self._executor.submit(socket.socket, family, type).result()

    def listen_socket(self, port: int) -> socket.socket:
        s = self.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))  # 0.0.0.0 inside the namespace: survives a DHCP address change
        s.listen(100)
        s.setblocking(False)
        return s

    async def stop(self) -> None:
        for proc in (self._dhcp, self._holder):
            if proc and proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), 5)
                except asyncio.TimeoutError:
                    proc.kill()
        if self._executor:
            self._executor.shutdown(wait=False)
        if self._ns_fd is not None:
            os.close(self._ns_fd)
            self._ns_fd = None
