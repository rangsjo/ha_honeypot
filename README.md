<img src="honeypot/logo.png" alt="Honeypot" width="250">

[![CI](https://github.com/rangsjo/ha_honeypot/actions/workflows/ci.yaml/badge.svg)](https://github.com/rangsjo/ha_honeypot/actions/workflows/ci.yaml)

A Home Assistant add-on that puts a fake **NAS** on your network and sends you a push notification the moment anything touches it.

Nothing legitimate ever connects to the honeypot. So any connection or login attempt means a device on your LAN is scanning or probing: a compromised IoT gadget, malware on a laptop, or someone on your Wi-Fi.

```
Honeypot: login attempt on ssh from Garage Pi
192.168.1.9 tried 'pi' / 'raspberry'
Known in HA as: Garage Pi
Hostname: raspberrypi.local, pi.lan
MAC: b8:27:eb:12:34:56 (Raspberry Pi Foundation)
Its open ports: 22 SSH, 80 HTTP
Activity: 12 events since 5 min ago on ssh, telnet · users tried: root, pi
```

## Features

- **Fake SSH, Telnet, FTP and HTTP login services**, plus TCP tripwires on RDP, VNC and MySQL ports. They log every credential tried and accept none.
- **Its own device on the LAN.** The honeypot gets its own MAC and DHCP lease, so it never looks like Home Assistant. It falls back to HA's IP when that isn't possible.
- **A different look on every install.** A random persona (hostname, OS banners, MAC vendor, web page) means scanners can't learn to recognise it.
- **Alerts that identify the intruder:** HA device name, hostnames (DNS/mDNS/NetBIOS), MAC vendor, open ports, activity summary.
- **Unprivileged after startup.** Once its network setup is done, the add-on drops root and all its admin rights, so a bug in a fake service doesn't give the attacker your HA machine.
- **Native HA integration.** Notifications go straight to your phone, with an *Ignore this device* button. Entities (`binary_sensor.honeypot_intrusion`, last intruder, events today) and a `honeypot_alert` event let you build automations.
- **Rate-limited alerts.** A port scan gives you one notification, not fifty. Tapping it opens the Honeypot panel with the full history.

## Install

[![Add repository to my Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Frangsjo%2Fha_honeypot)

Or manually: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**, add `https://github.com/rangsjo/ha_honeypot`. Then install **Honeypot**, add your phone under **Notify targets** in its Configuration tab, and start it. No YAML needed.

This is a Home Assistant **add-on**, so it needs Home Assistant OS or Supervised. HACS can't install add-ons.

## Documentation

Setup, options, the own-IP requirements and security notes are in [honeypot/DOCS.md](honeypot/DOCS.md), which is the add-on's Documentation tab in HA.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-test.txt
.venv/bin/pytest
```

Run it outside HA with `docker compose up -d --build` (see `docker-compose.yaml`; panel at http://localhost:8199). To test changes on your own HA as a local add-on, run `./sync-to-ha.sh` (needs the SSH add-on). To release, bump `version` in `honeypot/config.json` and add a `CHANGELOG.md` entry. On push, the *Publish* workflow builds both images on GHCR and tags a GitHub release, which takes about 5 minutes. HA may show the update a little before the images are ready. `sync-to-ha.sh` removes the `image` key, so your local copy is built from source.

```
repository.yaml          HA add-on repository manifest
honeypot/                add-on (Docker build context)
  config.json            manifest: host_network, ingress, privileges, options
  DOCS.md, README.md, CHANGELOG.md, translations/   what HA shows in the store
  main.py                startup: persona, own IP, services, panel, alerts
  config.py              options.json + env-var overrides
  persona.py             random per-install banners/hostname/MAC, saved in /data
  privileges.py          drop root + all capabilities after startup
  netns.py, udhcpc.script  own IP: macvlan + private network namespace + DHCP
  services/              ssh, telnet, ftp, http, tripwire
  enrich.py              device identification (vendor, DNS/mDNS/NetBIOS, HA entities, ports)
  notifier.py            HA webhook, per-IP cooldown, alert text
  events.py              event/alert log in /data, ARP→MAC lookup
  ui.py, templates/      ingress panel
tests/                   unit tests and end-to-end tests that drive each fake service as a client
```

## Support

If the honeypot caught something on your network, or you just like it, you can [buy me a coffee](https://buymeacoffee.com/jojononasos). ☕

[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-ffdd00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/jojononasos)

## License

MIT, see [LICENSE](LICENSE).
