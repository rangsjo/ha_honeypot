"""Alert channels that use the HA API: phone notifications and an HA event."""

import ipaddress

from ha_api import HAClient

IGNORE_ACTION = "HONEYPOT_IGNORE_"


def notify_service(target: str) -> str:
    """'notify.mobile_app_x' or 'mobile_app_x' -> 'mobile_app_x'."""
    return target.strip().removeprefix("notify.")


def notification_data(payload: dict) -> dict:
    """Companion-app extras: tap opens the panel, breaks through Focus, Ignore button."""
    panel = payload.get("panel_path") or "/"
    data = {
        "url": panel,                 # iOS
        "clickAction": panel,         # Android
        "group": "honeypot",
        "push": {"interruption-level": "time-sensitive"},
        "priority": "high",
        "ttl": 0,
    }
    ip = payload.get("src_ip")
    try:
        ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return data
    data["actions"] = [{"action": f"{IGNORE_ACTION}{ip}", "title": "Ignore this device"}]
    return data


def parse_ignore_action(action: str) -> str | None:
    """IP from an 'Ignore this device' action, or None for any other action."""
    if not action or not action.startswith(IGNORE_ACTION):
        return None
    ip = action[len(IGNORE_ACTION):]
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


def notify_channel(ha: HAClient, target: str):
    service = notify_service(target)

    async def send(payload: dict) -> None:
        await ha.call_service("notify", service, {
            "title": payload["title"],
            "message": payload["message"],
            "data": notification_data(payload),
        })
    return send

