# Honeypot

Fake network services that alert you when anything on your LAN touches them. Nothing legitimate ever connects to them, so every connection or login attempt means a device on your network is scanning or probing.

## How it works

By default the honeypot appears as a **separate device on your LAN** (`own_ip`). It has its own MAC address and its own IP from your router, under a hostname such as `diskstation`. It offers:

| Service | Default port | What it captures |
|---|---|---|
| SSH (real handshake) | 22 (2222 if 22 is taken) | username + password, or public-key fingerprint |
| Telnet login prompt | 23 | username + password |
| FTP | 21 | `USER` / `PASS` |
| HTTP (web admin login page) | 80 | requested path, User-Agent, form and Basic-auth credentials |
| TCP tripwires (RDP, VNC, MySQL) | 3389, 5900, 3306 | the connection and its first bytes |

Every login is refused. On first start the add-on picks a random but consistent **persona**: hostname, SSH/Telnet/FTP banners from one OS, web page title, `Server` header and a MAC vendor (Synology, QNAP, Intel or Raspberry Pi). It keeps that persona in `/data/persona.json`. Every install looks different, so scanners can't learn to skip this add-on.

## Setup

### 1. Create the notification automation

Settings → Automations → Create → ⋮ → Edit in YAML. Replace `notify.mobile_app_your_phone` with your phone's action (find it under Developer tools → Actions, search `mobile_app`).

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
  # Optional: keep a copy in HA's notification bell until dismissed.
  - action: persistent_notification.create
    data:
      title: "{{ trigger.json.title }}"
      message: "{{ trigger.json.message }}"
```

On iPhone, turn on **Settings → Notifications → Home Assistant → Time Sensitive Notifications**.

### 2. Start and test

Start the add-on and open the **Honeypot** panel in the sidebar. The top line shows the honeypot's own IP, MAC and hostname, and which services are listening. Press **Send test notification**, then try it from another computer (not from HA itself):

```bash
ssh root@<honeypot-ip>
curl http://<honeypot-ip>/
nc <honeypot-ip> 23
```

## What an alert looks like

```
Honeypot: login attempt on ssh from Garage Pi
192.168.1.9 tried 'pi' / 'raspberry'
Known in HA as: Garage Pi
Hostname: raspberrypi.local, pi.lan
MAC: b8:27:eb:12:34:56 (Raspberry Pi Foundation)
Its open ports: 22 SSH, 80 HTTP
Activity: 12 events since 5 min ago on ssh, telnet · users tried: root, pi
```

The device details come from:
- the MAC vendor database
- reverse DNS (your router's DHCP names), mDNS/Bonjour and NetBIOS
- HA entities that list the IP or MAC (router integrations, device trackers)
- a quick check of the intruder's own ports

The alert also warns when the source is outside your LAN.

**Rate limiting:** each source IP gets at most one *connection* alert and one *login* alert per `notify_cooldown`. Later alerts say how many events were held back.

**Nothing is lost:** the panel's **Alerts** section keeps every alert with full details, including alerts that could not be delivered while HA was restarting. **All events** lists every single connection.

The webhook payload also has the raw fields, if you want your own formatting or a sensor: `service`, `kind` (`connect`/`login`), `src_ip`, `src_port`, `mac`, `username`, `password`, `detail`, `suppressed`, `ts`, `host` and `activity`.

## Own IP

`own_ip` (on by default) puts the fake services on a macvlan interface with its own MAC, inside a private network namespace, and gets an IP for it over DHCP.
- **HA is not touched:** its own networking, routing and ARP stay unchanged.
- **Nothing leads back to HA:** intruders never see traffic from HA's IP, because the device lookups also run from the honeypot's IP.
- **Clean shutdown:** when the add-on stops, it releases the lease and the interface disappears.

Requirements:
- **HA must be on Ethernet.** Wi-Fi access points usually refuse a second MAC address from one client.
- **In a VM**, the virtual network adapter must be *bridged* and allow other MAC addresses: VirtualBox: *Promiscuous Mode: Allow All*; Hyper-V: *MAC address spoofing*; Proxmox/KVM bridges work by default.
- HA itself can't reach the honeypot's IP (a macvlan limitation), so test from another device.

Your router may list the honeypot as a new device (often named after the MAC vendor, e.g. QNAP) even when own IP fails. That happens when the DHCP request goes out but the reply can't get back in, the typical VM symptom. If own IP setup fails, the add-on logs why and **falls back to HA's IP**. In that mode SSH moves to port 2222 when 22 is taken by the SSH add-on. The panel shows which mode is active.

## Options

| Option | Default | |
|---|---|---|
| `ha_url` | `http://127.0.0.1:8123` | Where to send the webhook. The add-on uses host networking, so localhost reaches HA. |
| `webhook_id` | `honeypot_alert` | Must match the automation's trigger. |
| `notify_cooldown` | `600` | Seconds between alerts per source IP and alert type. `0` = alert on every event. |
| `ignore_ips` | `[]` | Never log or alert for these IPs (e.g. your network scanner). |
| `ssh_port` / `ssh_fallback_port` | `22` / `2222` | SSH uses the fallback port if the first one is taken. |
| `telnet_port`, `ftp_port`, `http_port` | `23`, `21`, `80` | `0` disables a service. |
| `tripwire_ports` | `[3389, 5900, 3306]` | Plain TCP listeners. |
| `probe_back` | `true` | Check a few of the intruder's ports to guess the device type. |
| `own_ip` | `true` | Appear as a separate LAN device (see above). |
| `own_ip_interface` | | Network interface to attach to. Default: the one with HA's default route. |
| `own_ip_address` / `own_ip_gateway` | | Static address such as `192.168.1.250/24` instead of DHCP. |
| `hostname`, `ssh_banner`, `telnet_banner`, `ftp_banner`, `http_title`, `http_server` | | Pin parts of the persona. Leave empty to keep the random one. |

If a port is already in use, that service shows as failed in the panel and the others keep running.

## Data

Everything lives in the add-on's `/data` and is included in HA backups:
- `events.jsonl`: every connection and login attempt
- `alerts.jsonl`: every alert with full details
- `hosts.json`: device details per source IP
- `persona.json`: this install's fake identity
- `ssh_host_ed25519_key`: the fake SSH server's host key

## Support

Bugs and ideas: [GitHub issues](https://github.com/rangsjo/ha_honeypot/issues). If you find the add-on useful, you can [buy me a coffee](https://buymeacoffee.com/jojononasos). ☕

## Security notes

- No service ever accepts a login or runs a command. They only read a few short lines, with timeouts and length limits.
- The panel is only reachable through HA (ingress), not from the LAN.
- `NET_ADMIN` and `SYS_ADMIN` are needed only to create the own-IP interface and namespace.
- **Do not port-forward these ports from your router.** This is a LAN tripwire. On the internet it would alert you constantly.
- Captured passwords are what intruders *tried*. If one of them is a real password of yours, a device on your LAN knows it. Change it.
