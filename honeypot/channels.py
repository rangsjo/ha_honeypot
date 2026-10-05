"""Alert channels that use the HA API: phone notifications and an HA event."""

import ipaddress

from ha_api import HAClient

IGNORE_ACTION = "HONEYPOT_IGNORE_"


def notify_service(target: str) -> str:
    """'notify.mobile_app_x' or 'mobile_app_x' -> 'mobile_app_x'."""
    return target.strip().removeprefix("notify.")


def notification_data(payload: dict, critical: bool = False) -> dict:
    """Companion-app extras: tap opens the panel, breaks through Focus, Ignore button.

    critical: also sound when the phone is on silent or Do Not Disturb (iOS
    critical alert at full volume; Android alarm stream).
    """
    panel = payload.get("panel_path") or "/"
    data = {
        "url": panel,                 # iOS
        "clickAction": panel,         # Android
        "group": "honeypot",
        "push": {"interruption-level": "time-sensitive"},
        "priority": "high",
        "ttl": 0,
    }
    if critical:
        data["push"] = {"interruption-level": "critical",
                        "sound": {"name": "default", "critical": 1, "volume": 1.0}}
        data["channel"] = "alarm_stream"
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


def notify_channel(ha: HAClient, target: str, critical: bool = False):
    service = notify_service(target)

    async def send(payload: dict) -> None:
        await ha.call_service("notify", service, {
            "title": payload["title"],
            "message": payload["message"],
            "data": notification_data(payload, critical),
        })
    return send


async def persistent_notification(ha: HAClient, payload: dict) -> None:
    """Keep the alert in HA's notification bell until dismissed, one per source device."""
    ip = payload.get("src_ip") or "test"
    await ha.call_service("persistent_notification", "create", {
        "title": payload["title"],
        "message": payload["message"],
        "notification_id": f"honeypot_{ip.replace('.', '_').replace(':', '_')}",
    })

