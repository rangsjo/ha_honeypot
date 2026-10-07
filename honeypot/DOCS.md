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
| MQTT broker | 1883 (own IP only) | client id, username + password |
| SMB file share | 445 (own IP only) | the SMB versions the client offers |
| TCP tripwires (RDP, VNC, MySQL) | 3389, 5900, 3306 | the connection and its first bytes |

In own-IP mode the honeypot also:
- **Detects network scans:** it sees every ARP broadcast on the LAN and alerts when one device asks for many addresses within seconds (a sweep, as scanners do before probing ports), or when a device pings it. A device that merely re-checks the honeypot's address, like a TV that saw the fake NAS over Bonjour, is only logged as a *lookup*. Your router is ignored.
- **Announces itself over mDNS/Bonjour** as a file server with SMB, SSH and web services, so it appears in Finder, file managers and network browsers and attracts curious people.

Every login is refused. On first start the add-on picks a random but consistent **persona**: hostname, SSH/Telnet/FTP banners from one OS, web page title, `Server` header and a MAC vendor (Synology, QNAP, Intel or Raspberry Pi). It keeps that persona in `/data/persona.json`. Every install looks different, so scanners can't learn to skip this add-on.

## Setup

### 1. Choose where alerts go

In the add-on's **Configuration** tab, add your phone to **Notify targets**, e.g. `notify.mobile_app_my_phone`. To find the name, go to Developer tools → Actions and search `mobile_app`. Add several targets to alert several phones. No automation is needed.

Turn on **Critical alerts** to make alerts sound even when the phone is on silent or Do Not Disturb. iOS asks once to allow critical alerts for the Home Assistant app. Each alert also stays in HA's notification bell until you dismiss it (option **Show in HA notifications**).

Alerts open the Honeypot panel when tapped, break through Focus on iPhone (turn on **Settings → Notifications → Home Assistant → Time Sensitive Notifications**), and have an **Ignore this device** button for false alarms, such as your own network scanner.

### 2. Start and test

Start the add-on and open the **Honeypot** panel in the sidebar. The top line shows the honeypot's own IP, MAC and hostname, and which services are listening. Press **Send test notification**, then try it from another computer (not from HA itself):

```bash
ssh root@<honeypot-ip>
curl http://<honeypot-ip>/
nc <honeypot-ip> 23
```

## Entities and automations

The add-on keeps these entities up to date (no MQTT needed):

| Entity | |
|---|---|
| `binary_sensor.honeypot_intrusion` | `on` for 5 minutes after any activity (device class *safety*) |
| `sensor.honeypot_last_intruder` | Best name of the last alerting device. Attributes: IP, MAC, vendor, service, username, password, time and the alert text |
| `sensor.honeypot_events_today` | Connections and login attempts today |

Every alert also fires a **`honeypot_alert` event**, which shows up in the logbook and works as an automation trigger. For example, to flash the hallway lights:

```yaml
triggers:
  - trigger: event
    event_type: honeypot_alert
actions:
  - action: light.turn_on
    target: { entity_id: light.hallway }
    data: { flash: long }
```

The event data has `title`, `message`, `service`, `kind` (`connect`/`login`), `src_ip`, `mac`, `username`, `password`, `host` and `activity`.

> **Upgrading from a webhook automation?** Set **Notify targets**, then delete your old *Honeypot alert* automation and clear `webhook_id`, or you'll get every alert twice.

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

**The panel** shows the last 14 days, the top devices and every event. Click a device to see its full history. **Nothing is lost:** the **Alerts** section keeps every alert with full details, including alerts that could not be delivered while HA was restarting. **All events** lists every single connection.

The webhook payload also has the raw fields, if you want your own formatting or a sensor: `service`, `kind` (`connect`/`login`), `src_ip`, `src_port`, `mac`, `username`, `password`, `detail`, `suppressed`, `ts`, `host` and `activity`.

## Own IP

`own_ip` (on by default) puts the fake services on a macvlan interface with its own MAC, inside a private network namespace, and gets an IP for it over DHCP.
- **HA is not touched:** its own networking, routing and ARP stay unchanged.
- **Nothing leads back to HA:** intruders never see traffic from HA's IP, because the device lookups also run from the honeypot's IP.
- **Clean shutdown:** when the add-on stops, it releases the lease and the interface disappears.

Requirements:
- **HA must be on Ethernet.** Wi-Fi access points usually refuse a second MAC address from one client.
- **In a VM**, the virtual network adapter must be *bridged* and allow other MAC addresses: VirtualBox: *Promiscuous Mode: Allow All* (then fully power off and start the VM); Hyper-V: *MAC address spoofing*; Proxmox/KVM bridges work by default. Some virtual network cards, such as VirtualBox's Intel PRO/1000, also need promiscuous mode *inside* HA. The add-on switches that on automatically when its first receive check fails, and logs it.
- HA itself can't reach the honeypot's IP (a macvlan limitation), so test from another device.

Your router may list the honeypot as a new device (often named after the MAC vendor, e.g. QNAP) even when own IP fails. That happens when the DHCP request goes out but the reply can't get back in, the typical VM symptom. If own IP setup fails, the add-on logs why and **falls back to HA's IP**. In that mode SSH moves to port 2222 when 22 is taken by the SSH add-on. The panel shows which mode is active.

## Options

| Option | Default | |
|---|---|---|
| `notify_targets` | `[]` | Notify actions that receive alerts, e.g. `notify.mobile_app_my_phone`. |
| `webhook_id` | | Optional: also POST alerts to this HA webhook. |
| `ha_url` | `http://127.0.0.1:8123` | Only used for the webhook. |
| `notify_cooldown` | `600` | Seconds between alerts per source IP and alert type. `0` = alert on every event. |
| `ignore_ips` | `[]` | Never log or alert for these IPs (e.g. your network scanner). |
| `ssh_port` / `ssh_fallback_port` | `22` / `2222` | SSH uses the fallback port if the first one is taken. |
| `telnet_port`, `ftp_port`, `http_port` | `23`, `21`, `80` | `0` disables a service. |
| `smb_port`, `mqtt_port` | `445`, `1883` | Own-IP mode only, so they never take the Samba or Mosquitto add-on's ports. `0` disables. |
| `tripwire_ports` | `[3389, 5900, 3306]` | Plain TCP listeners. |
| `detect_discovery` | `true` | Alert on ARP sweeps of the LAN and pings of the honeypot (own-IP mode). |
| `mdns` | `true` | Announce the fake NAS over mDNS (own-IP mode). |
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
- `ignored.json`: devices ignored from a notification or the panel
- `hosts.json`: device details per source IP
- `persona.json`: this install's fake identity
- `ssh_host_ed25519_key`: the fake SSH server's host key

## Support

Bugs and ideas: [GitHub issues](https://github.com/rangsjo/ha_honeypot/issues). If you find the add-on useful, you can [buy me a coffee](https://buymeacoffee.com/jojononasos). ☕

## Security notes

- No service ever accepts a login or runs a command. They only read a few short lines, with timeouts and length limits.
- The panel is only reachable through HA (ingress), not from the LAN.
- **The fake services run unprivileged.** Root, `NET_ADMIN` and `SYS_ADMIN` are needed only at startup, to create the own-IP interface and namespace and to open the low ports. After that the add-on switches to an unprivileged user with no capabilities and *no new privileges*. A bug in a fake service then gives an attacker an unprivileged process, not control over the HA machine. Two tiny helpers keep root: the one holding the namespace open, and the DHCP client renewing the honeypot's lease. The panel's `privileges` line confirms the drop.
- **In a VM, promiscuous mode** lets the HA VM receive traffic addressed to other MACs that reaches the host's network card. On a switched network that's mostly the host's own traffic. If HA were compromised, it could read that traffic. On a dedicated VM host that's negligible. On your everyday PC, weigh it against the better disguise, or turn off `own_ip`.
- **Do not port-forward these ports from your router.** This is a LAN tripwire. On the internet it would alert you constantly.
- Captured passwords are what intruders *tried*. If one of them is a real password of yours, a device on your LAN knows it. Change it.
