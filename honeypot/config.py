"""Load options from the Supervisor's options.json, with env-var overrides for standalone use."""

import json
import os
from pathlib import Path

DEFAULTS = {
    "ha_url": "http://127.0.0.1:8123",
    "notify_targets": [],
    "webhook_id": "",
    "notify_cooldown": 600,
    "ignore_ips": [],
    "ssh_port": 22,
    "ssh_fallback_port": 2222,
    "telnet_port": 23,
    "ftp_port": 21,
    "http_port": 80,
    "smb_port": 445,
    "mqtt_port": 1883,
    "tripwire_ports": [3389, 5900, 3306],
    "probe_back": True,
    "mdns": True,
    "detect_discovery": True,
    # Persona overrides; empty = use the random per-install persona.
    "hostname": "",
    "ssh_banner": "",
    "telnet_banner": "",
    "ftp_banner": "",
    "http_title": "",
    "http_server": "",
    # Own IP: run the services as a separate LAN device (see netns.py).
    "own_ip": True,
    "own_ip_interface": "",
    "own_ip_address": "",
    "own_ip_gateway": "",
    "ui_port": 8199,
}


# Env var names that differ from KEY.upper(): HOSTNAME is set by Docker and the
# Supervisor to the container name, which would leak into the fake banners.
ENV_NAMES = {"hostname": "FAKE_HOSTNAME"}


def _parse_env(value: str, default):
    if isinstance(default, list):
        items = [v.strip() for v in value.split(",") if v.strip()]
        return [int(v) for v in items] if default and isinstance(default[0], int) else items
    if isinstance(default, bool):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(default, int):
        return int(value)
    return value


def load(options_path: Path | None = None) -> dict:
    options_path = options_path or Path(os.getenv("DATA_DIR", "/data")) / "options.json"
    cfg = dict(DEFAULTS)
    if options_path.exists():
        cfg.update(json.loads(options_path.read_text()))
    for key, default in DEFAULTS.items():
        env = os.getenv(ENV_NAMES.get(key, key.upper()))
        if env is not None:
            cfg[key] = _parse_env(env, default)
    return cfg
