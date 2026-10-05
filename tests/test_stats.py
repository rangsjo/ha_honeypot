import time

from stats import summarize


def test_summarize_days_and_top_devices():
    now = time.mktime((2026, 10, 6, 12, 0, 0, 0, 0, -1))
    events = [
        {"ts": now, "src_ip": "192.168.1.9", "kind": "login"},
        {"ts": now - 60, "src_ip": "192.168.1.9", "kind": "connect"},
        {"ts": now - 86400, "src_ip": "192.168.1.20", "kind": "connect"},
        {"ts": now - 86400 * 30, "src_ip": "192.168.1.20", "kind": "connect"},  # outside the window
    ]
    s = summarize(events, {"192.168.1.9": {"ha_entities": ["Garage Pi"]}}, days=14, now=now)
    assert len(s["days"]) == 14
    assert s["days"][-1] == {"day": "2026-10-06", "events": 2, "logins": 1}
    assert s["days"][-2]["events"] == 1
    assert s["top"][0] == {"ip": "192.168.1.9", "name": "Garage Pi", "events": 2, "last_seen": now}
    assert s["top"][1]["ip"] == "192.168.1.20" and s["top"][1]["events"] == 2
    assert s["total"] == 4
