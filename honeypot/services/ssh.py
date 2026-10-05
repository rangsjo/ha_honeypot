"""Fake OpenSSH server: real SSH handshake, every authentication attempt is logged and refused."""

import asyncio
import logging
from pathlib import Path

import asyncssh

from services.common import Report

DEFAULT_VERSION = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"

logging.getLogger("asyncssh").setLevel(logging.WARNING)


class _Server(asyncssh.SSHServer):
    def __init__(self, report: Report, delay: float):
        self._report = report
        self._delay = delay
        self._peer = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._peer = conn.get_extra_info("peername")
        self._report("ssh", self._peer, "connect",
                     detail=f"client {conn.get_extra_info('client_version', '')}".strip())

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        self._report("ssh", self._peer, "login", username=username, password=password)
        await asyncio.sleep(self._delay)
        return False

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        self._report("ssh", self._peer, "login", username=username,
                     detail=f"publickey {key.get_fingerprint()}")
        return False


def load_host_key(path: Path) -> asyncssh.SSHKey:
    if path.exists():
        return asyncssh.read_private_key(str(path))
    key = asyncssh.generate_private_key("ssh-ed25519")
    path.parent.mkdir(parents=True, exist_ok=True)
    key.write_private_key(str(path))
    return key


async def start(port: int, report: Report, host_key_path: Path, version: str = DEFAULT_VERSION,
                host: str = "0.0.0.0", delay: float = 1.0, sock=None) -> asyncssh.SSHAcceptor:
    where = {"sock": sock} if sock is not None else {"host": host, "port": port}
    return await asyncssh.listen(
        server_factory=lambda: _Server(report, delay), **where,
        server_host_keys=[load_host_key(host_key_path)],
        server_version=version,
        login_timeout=60,
    )
