"""Summary numbers for the panel."""

import time
from collections import Counter


def summarize(events: list[dict], hosts: dict[str, dict], days: int = 14, now: float | None = None,
              top: int = 10) -> dict:
    now = now if now is not None else time.time()
    day_keys = [time.strftime("%Y-%m-%d", time.localtime(now - 86400 * i)) for i in range(days - 1, -1, -1)]
    per_day = Counter()
    logins_per_day = Counter()
    per_ip = Counter()
    last_seen: dict[str, float] = {}
    for e in events:
        ts = e.get("ts", 0)
        day = time.strftime("%Y-%m-%d", time.localtime(ts))
        per_day[day] += 1
        if e.get("kind") == "login":
            logins_per_day[day] += 1
        ip = e.get("src_ip")
        if ip:
            per_ip[ip] += 1
            last_seen[ip] = max(last_seen.get(ip, 0), ts)

    def name(ip: str) -> str:
        h = hosts.get(ip) or {}
        for key in ("ha_entities", "mdns_name", "netbios_name", "dns_name"):
            v = h.get(key)
            if v:
                return v[0] if isinstance(v, list) else v
        return h.get("vendor") or ""

    return {
        "days": [{"day": d, "events": per_day[d], "logins": logins_per_day[d]} for d in day_keys],
        "top": [{"ip": ip, "name": name(ip), "events": n, "last_seen": last_seen[ip]}
                for ip, n in per_ip.most_common(top)],
        "total": len(events),
    }
