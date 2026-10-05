# Changelog

## 1.1.1

- **Own IP diagnostics:** DHCP asks for broadcast replies, so the honeypot gets a lease even where traffic to its own MAC is filtered. The receive check then reports precisely whether broadcast or unicast traffic is failing.

## 1.1.0

- **Runs unprivileged after startup:** once own IP is set up and the ports are open, the add-on switches to an unprivileged user with no capabilities. The fake services, which face attackers, no longer run as root with `NET_ADMIN`/`SYS_ADMIN`. The panel shows the result.
- **Own IP helpers are stopped through a pipe** instead of signals, so the DHCP lease is released on stop (and if the add-on crashes).
- Clearer message when the network namespace can't be created.

## 1.0.1

- **Clearer own IP errors:** when DHCP replies or traffic for the honeypot's MAC don't arrive, the log and panel say so and point to the VM network setting.
- **Receive check:** own IP now confirms it can receive traffic (via the gateway) before using the address. A static address that can't be reached falls back to HA's IP instead of failing silently.

## 1.0.0

- **Own IP is now the default.** The honeypot appears as a separate LAN device with its own MAC and DHCP lease. If setup fails, it falls back to HA's IP.
- **SSH defaults to port 22**, with a fallback to `ssh_fallback_port` (2222) when 22 is taken, e.g. by the SSH add-on in shared-IP mode.
- **Panel no longer reachable from the LAN:** it is bound to HA's internal network.
- **Intruder MAC addresses are found in own-IP mode** (they were only looked up in HA's ARP table).
- **Store polish:** icon, logo, documentation tab and option descriptions.

## 0.5.0

- `own_ip` option: run the services as a separate LAN device (macvlan in a private network namespace, DHCP under the persona's hostname). Lookups against the intruder are sent from the honeypot's IP.
- Fix: the persona hostname picked up the container's `HOSTNAME` (shown as `local-honeypot` in the telnet prompt).

## 0.4.0

- Random per-install persona (hostname, banners, web page identity) so scanners can't fingerprint the add-on.

## 0.3.1

- Fix tapping a notification giving 404 on HA 2026.9+.

## 0.3.0

- Alerts and device details are saved in `/data` and shown in the panel's **Alerts** section, including alerts that could not be delivered.
- Tapping a notification can open the Honeypot panel (`panel_path` in the payload).

## 0.2.0

- Alerts identify the device: HA entity name, hostnames (DNS, mDNS, NetBIOS), MAC vendor, open ports, activity summary.

## 0.1.0

- First release: fake SSH, Telnet, FTP, HTTP and TCP tripwires, alerts through an HA webhook with per-IP rate limiting, ingress panel.
