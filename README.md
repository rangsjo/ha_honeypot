# Honeypot

A Home Assistant add-on that runs fake network services on your LAN. Nothing legitimate ever talks to them, so **any** connection or login attempt means a device on your network is scanning or probing, and you get a push notification on your phone.

**Fake services:**

| Service | Default port | What it captures |
|---|---|---|
| SSH (real handshake, OpenSSH banner) | 2222 | username + password, or public-key fingerprint |
| Telnet (`nas login:` prompt) | 23 | username + password |
| FTP (vsFTPd banner) | 21 | `USER` / `PASS` |
| HTTP ("Router Administration" login page) | 80 | requested path, User-Agent, form and Basic-auth credentials |
| TCP tripwires (RDP, VNC, MySQL) | 3389, 5900, 3306 | the connection and its first bytes |

Every login is refused. Each alert tries to identify the device behind the IP:

```
Honeypot: login attempt on ssh from Garage Pi
192.168.1.9 tried 'pi' / 'raspberry'
Known in HA as: Garage Pi
Hostname: raspberrypi.local, pi.lan
MAC: b8:27:eb:12:34:56 (Raspberry Pi Foundation)
Its open ports: 22 SSH, 80 HTTP
Activity: 12 events since 5 min ago on ssh, telnet · users tried: root, pi
```

The details come from the MAC vendor database, reverse DNS (your router's DHCP names), mDNS/Bonjour, NetBIOS, HA entities that list the IP or MAC (router integrations, device trackers), and a quick check of the intruder's own ports. The add-on also warns when the source is outside your LAN.

**Alert rate limiting:** a port scan touches every service in a second, and a brute-forcer tries hundreds of passwords. Each source IP gets at most one *connection* alert and one *login* alert per `notify_cooldown` (default 10 min). Later alerts say how many events were held back. Everything is logged regardless, in the sidebar panel and in `/data/events.jsonl`.

---

## Option A: Home Assistant add-on (recommended)

### 1. Install

**From the repository (private repo):** create a fine-grained GitHub token scoped to this repo only, with *Contents: Read-only*. Then in HA: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**, add `https://<TOKEN>@github.com/rangsjo/ha_honeypot`, and install **Honeypot**.

**Or as a local add-on:** run `./sync-to-ha.sh` (needs the SSH add-on), then **⋮ → Check for updates** in the Add-on Store and install it from *Local add-ons*.

Bump `version` in `honeypot/config.json` on every release you want HA to pick up.

### 2. Configure

```yaml
ha_url: http://127.0.0.1:8123     # the add-on uses host networking, so localhost reaches HA Core
webhook_id: honeypot_alert
notify_cooldown: 600
ignore_ips: []                    # e.g. your own network-monitoring box
ssh_port: 2222
telnet_port: 23
ftp_port: 21
http_port: 80
tripwire_ports: [3389, 5900, 3306]
probe_back: true                  # check a few of the intruder's own ports to guess the device type
```

Set a port to `0` to disable that service. If a port is already taken (for example 22 by the SSH add-on, or 445 by Samba), that service logs an error and the rest keep running. The panel shows each service's status.

> **Tip:** attackers try port 22 first. If you move the *Terminal & SSH* add-on to a different port, set `ssh_port: 22` here for a much better trap.

### 3. Create the notification automation

```yaml
alias: Honeypot alert
triggers:
  - trigger: webhook
    webhook_id: honeypot_alert
    allowed_methods:
      - POST
    local_only: true
actions:
  - action: notify.mobile_app_your_phone
    data:
      title: "{{ trigger.json.title }}"
      message: "{{ trigger.json.message }}"
      data:
        url: "{{ trigger.json.panel_path }}"           # iOS: tapping opens the Honeypot panel
        clickAction: "{{ trigger.json.panel_path }}"   # Android
        push:
          interruption-level: time-sensitive   # iOS: break through Focus
        priority: high                         # Android
        ttl: 0
  # Keep a copy in HA's notification bell until you dismiss it there.
  - action: persistent_notification.create
    data:
      title: "{{ trigger.json.title }}"
      message: "{{ trigger.json.message }}"
```

Every alert is also saved by the add-on itself, so nothing is lost if you swipe a notification away. The **Alerts** section of the panel shows each alert's full text and device details, and it keeps alerts that could not be delivered (for example while HA was restarting). Files in the add-on's `/data`: `alerts.jsonl`, `events.jsonl`, `hosts.json`.

The payload also contains the raw fields if you want your own formatting or a dashboard sensor: `service`, `kind` (`connect`/`login`), `src_ip`, `src_port`, `mac`, `username`, `password`, `detail`, `suppressed`, `ts`, plus `host` (vendor, names, open ports) and `activity` (event count, services, usernames).

### 4. Start and test

Start the add-on, open the **Honeypot** sidebar panel and press **Send test notification**. Then try it from a laptop:

```bash
ssh -p 2222 root@homeassistant.local
telnet homeassistant.local
curl http://homeassistant.local/
```

---

## Option B: Standalone Docker Compose

```bash
docker compose up -d --build     # edit HA_URL etc. in docker-compose.yaml first
```

The UI is at http://localhost:8199.

---

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-test.txt
.venv/bin/pytest
```

## Architecture

```
repository.yaml          HA add-on repository manifest
sync-to-ha.sh            push the add-on to HA as a local add-on
docker-compose.yaml      standalone deployment
honeypot/                add-on source (Docker build context)
  config.json            add-on manifest (host_network, ingress, options)
  run.sh / main.py       startup: launch services, UI, wire events to notifier
  config.py              options.json + env-var overrides
  events.py              event/alert log (memory + /data/events.jsonl) and ARP→MAC lookup
  notifier.py            HA webhook with per-IP cooldown, alert formatting
  enrich.py              device identification (vendor, DNS/mDNS/NetBIOS, HA entities, ports)
  ui.py, templates/      ingress panel (ingress-only when running under Supervisor)
  services/              ssh, telnet, ftp, http, tripwire
tests/                   end-to-end tests that drive each fake service as a client
```

## Security notes

- The add-on needs `host_network` so the services sit on HA's LAN IP and the ARP table is readable. It does **not** request any other privileges.
- No service ever accepts a login or runs a command. They only read a few short lines with timeouts and length limits.
- The UI port (8199) is open on the host, but it refuses every client except the Supervisor's ingress proxy.
- **Do not port-forward these ports from your router.** This is a LAN tripwire. On the internet it would just alert you constantly.
- Captured passwords are what intruders *tried*. If one of them is a real password of yours, a device on your LAN knows it. Change it.
