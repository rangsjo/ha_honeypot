"""Per-install identity for the fake services.

If every install showed the same banners, scanners could fingerprint the
honeypot once and skip it everywhere. Instead each install picks a random,
internally consistent persona on first start and keeps it in /data, so it stays
stable across restarts. Any field can be pinned with an add-on option.
"""

import json
import logging
import random
from pathlib import Path

log = logging.getLogger(__name__)

# SSH, telnet and FTP banners that plausibly come from the same machine.
SYSTEMS = [
    {"ssh_banner": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", "telnet_banner": "Ubuntu 22.04.4 LTS",
     "ftp_banner": "220 (vsFTPd 3.0.5)", "ouis": "pc"},
    {"ssh_banner": "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "telnet_banner": "Ubuntu 24.04.1 LTS",
     "ftp_banner": "220 (vsFTPd 3.0.5)", "ouis": "pc"},
    {"ssh_banner": "OpenSSH_9.2p1 Debian-2+deb12u3", "telnet_banner": "Debian GNU/Linux 12",
     "ftp_banner": "220 ProFTPD Server (Debian)", "ouis": "nas"},
    {"ssh_banner": "OpenSSH_8.4p1 Debian-5+deb11u3", "telnet_banner": "Debian GNU/Linux 11",
     "ftp_banner": "220 ProFTPD 1.3.7a Server (Debian)", "ouis": "nas"},
    {"ssh_banner": "OpenSSH_9.2p1 Debian-2+deb12u3", "telnet_banner": "Raspbian GNU/Linux 12",
     "ftp_banner": "220 (vsFTPd 3.0.3)", "ouis": "pi"},
    {"ssh_banner": "dropbear_2022.83", "telnet_banner": "",
     "ftp_banner": "220 Welcome to FTP service.", "ouis": "nas"},
]

# Vendor prefixes for the own_ip MAC, so its vendor lookup fits the persona.
# Universally administered (unlike phones' random MACs), like real hardware.
OUIS = {
    "pc": ["00:1b:21", "3c:fd:fe", "00:15:17"],          # Intel NICs
    "nas": ["00:11:32", "24:5e:be"],                     # Synology, QNAP
    "pi": ["dc:a6:32", "d8:3a:dd", "2c:cf:67"],          # Raspberry Pi
}

HOSTNAMES = ["nas", "diskstation", "storage", "backup", "fileserver", "mediaserver",
             "homeserver", "plex", "raspberrypi", "ubuntu", "nvr", "server", "media", "files"]

WEB_UIS = [
    {"http_title": "Router Administration", "http_server": "lighttpd/1.4.59"},
    {"http_title": "Web Management", "http_server": "lighttpd/1.4.45"},
    {"http_title": "NAS Login", "http_server": "nginx"},
    {"http_title": "Network Storage", "http_server": "Apache/2.4.57 (Debian)"},
    {"http_title": "Network Camera", "http_server": "GoAhead-Webs"},
    {"http_title": "Admin Login", "http_server": "mini_httpd/1.30 26Oct2018"},
    {"http_title": "Login", "http_server": "nginx/1.22.1"},
]

FIELDS = ("hostname", "ssh_banner", "telnet_banner", "ftp_banner", "http_title", "http_server", "mac")


def generate(rng: random.Random | None = None) -> dict:
    rng = rng or random.SystemRandom()
    system = dict(rng.choice(SYSTEMS))
    oui = rng.choice(OUIS[system.pop("ouis")])
    mac = oui + "".join(f":{rng.randrange(256):02x}" for _ in range(3))
    return {"hostname": rng.choice(HOSTNAMES), **system, **rng.choice(WEB_UIS), "mac": mac}


def load_or_create(path: Path | None, overrides: dict | None = None) -> dict:
    """Saved persona (created on first call), with any non-empty overrides on top."""
    persona = None
    if path and path.exists():
        try:
            persona = json.loads(path.read_text())
        except (OSError, ValueError) as e:
            log.warning("Could not read %s, making a new persona: %s", path, e)
    if not persona or any(f not in persona for f in FIELDS):
        persona = {**generate(), **(persona or {})}
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(persona, indent=2))
    pinned = {k: v for k, v in (overrides or {}).items() if k in FIELDS and v}
    return {**persona, **pinned}
