# Security policy

The honeypot deliberately talks to attackers, so security bugs in it matter. Thank you for reporting them responsibly.

## Reporting a vulnerability

Please **don't open a public issue**. Report privately through GitHub: **Security → Report a vulnerability** on this repository. You'll get an answer within a week.

Especially relevant:
- Anything that lets a client of a fake service run code, read files or escape the add-on's unprivileged user.
- Ways to make the add-on act on its host network beyond its own interface.
- Injection into notifications, the panel or Home Assistant through captured data (usernames, passwords, banners, hostnames).

## Supported versions

Only the latest release gets fixes. Home Assistant shows when an update is available.
