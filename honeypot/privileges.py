"""Drop root once the honeypot is set up.

The fake services are the one part of the add-on that talks to attackers on
purpose, so they shouldn't run with the root + NET_ADMIN + SYS_ADMIN the
own-IP setup needs. Those are only needed at startup: once the namespace
exists and the (low) ports are bound, the process switches to an unprivileged
user. Switching away from uid 0 clears all capabilities, and glibc applies
setuid to every thread, so nothing privileged is left in this process.

The udhcpc helper started earlier keeps root, since it has to configure the
honeypot's interface on lease renewals. It only talks DHCP.
"""

import ctypes
import logging
import os
import pwd
import re
from pathlib import Path

log = logging.getLogger(__name__)

USER = "honeypot"
PR_SET_NO_NEW_PRIVS = 38


def _chown_tree(path: Path, uid: int, gid: int) -> None:
    os.chown(path, uid, gid)
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            os.chown(os.path.join(root, name), uid, gid, follow_symlinks=False)


def privileged_threads(proc: Path = Path("/proc/self/task")) -> list[str]:
    """Threads that still run as root or hold any capability (should be none)."""
    bad = []
    for status in proc.glob("*/status"):
        text = status.read_text()
        uids = re.search(r"^Uid:\s+(.*)$", text, re.M).group(1).split()
        cap_eff = int(re.search(r"^CapEff:\s+([0-9a-f]+)$", text, re.M).group(1), 16)
        cap_prm = int(re.search(r"^CapPrm:\s+([0-9a-f]+)$", text, re.M).group(1), 16)
        if "0" in uids or cap_eff or cap_prm:
            bad.append(status.parent.name)
    return bad


def drop(data_dir: Path, user: str = USER) -> str:
    """Switch to `user` and hand it data_dir. Returns a status line for the panel."""
    if os.geteuid() != 0:
        return f"not root (uid {os.geteuid()})"
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        log.error("User %r missing; keeping root", user)
        return f"KEPT ROOT: user {user!r} missing"

    _chown_tree(data_dir, pw.pw_uid, pw.pw_gid)
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    try:
        ctypes.CDLL(None, use_errno=True).prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    except (OSError, AttributeError):
        pass

    bad = privileged_threads()
    if bad:
        log.error("Threads still privileged after dropping root: %s", bad)
        return f"PARTIAL: threads {bad} still privileged"
    log.info("Dropped root: running as %s with no capabilities", user)
    return f"dropped: running as {user}, no capabilities"
