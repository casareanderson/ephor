"""What an agent can actually *reach* — the question the egress tools don't answer.

Knowing an agent talked to example.com is half the picture. The other half is blast radius: if that agent
were prompt-injected or compromised, what could it touch? Ephor reads this straight from the kernel's view of
the process, no guessing:

  identity      uid/gid and supplementary groups it runs as (root? docker? sudo group?)
  capabilities  the effective Linux capabilities in CapEff (CAP_NET_ADMIN, CAP_SYS_ADMIN, ... decoded by name)
  sudo          whether `sudo -ln` shows passwordless escalation for the owning user (best-effort)
  secrets       which of the configured secret paths the process's user can actually read

This is a read-only snapshot of privilege, not a guarantee of intent. It's meant to make "this scraper runs as
root and can read /run/secrets" visible *before* something goes wrong.
"""
from __future__ import annotations

import os
import subprocess

# CapEff bit -> name. Covers the capabilities that matter for blast-radius; unknown bits print as cap_<n>.
_CAPS = {
    0: "chown", 1: "dac_override", 2: "dac_read_search", 3: "fowner", 4: "fsetid", 5: "kill",
    6: "setgid", 7: "setuid", 8: "setpcap", 9: "linux_immutable", 10: "net_bind_service",
    11: "net_broadcast", 12: "net_admin", 13: "net_raw", 14: "ipc_lock", 15: "ipc_owner",
    16: "sys_module", 17: "sys_rawio", 18: "sys_chroot", 19: "sys_ptrace", 20: "sys_pacct",
    21: "sys_admin", 22: "sys_boot", 23: "sys_nice", 24: "sys_resource", 25: "sys_time",
    26: "sys_tty_config", 27: "mknod", 28: "lease", 29: "audit_write", 30: "audit_control",
    31: "setfcap", 32: "mac_override", 33: "mac_admin", 34: "syslog", 35: "wake_alarm",
    36: "block_suspend", 37: "audit_read", 38: "perfmon", 39: "bpf", 40: "checkpoint_restore",
}

# The scary ones — surfaced first and flagged.
_HIGH_RISK = {"sys_admin", "sys_ptrace", "sys_module", "sys_rawio", "net_admin", "net_raw",
              "dac_override", "dac_read_search", "sys_boot", "bpf"}


def _status(pid: int) -> dict:
    out = {}
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def capabilities(pid: int) -> list[str]:
    """Decode CapEff for a pid into capability names (empty list = no effective capabilities)."""
    st = _status(pid)
    raw = st.get("CapEff", "0")
    try:
        mask = int(raw, 16)
    except ValueError:
        return []
    if mask == 0:
        return []
    # full set -> report compactly
    names = []
    for bit in range(0, 64):
        if mask & (1 << bit):
            names.append(_CAPS.get(bit, f"cap_{bit}"))
    return names


def identity(pid: int) -> dict:
    st = _status(pid)
    uid = st.get("Uid", "").split()[0] if st.get("Uid") else ""
    gid = st.get("Gid", "").split()[0] if st.get("Gid") else ""
    groups = []
    try:
        uid_i = int(uid)
        import grp
        import pwd

        name = pwd.getpwuid(uid_i).pw_name
        for g in grp.getgrall():
            if name in g.gr_mem:
                groups.append(g.gr_name)
        try:
            pg = grp.getgrgid(pwd.getpwuid(uid_i).pw_gid).gr_name
            if pg not in groups:
                groups.append(pg)
        except KeyError:
            pass
    except (ValueError, KeyError, ImportError):
        name = uid
    return {"uid": uid, "user": name, "gid": gid, "groups": sorted(groups)}


def sudo_nopasswd(user: str) -> str:
    """Best-effort: 'yes'/'limited'/'no'/'unknown'. Only meaningful when Ephor itself runs as root."""
    if os.geteuid() != 0 or not user or user.isdigit():
        return "unknown"
    try:
        r = subprocess.run(["sudo", "-ln", "-U", user], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    text = r.stdout.lower()
    if "nopasswd: all" in text or "(all : all) all" in text:
        return "yes"
    if "nopasswd" in text:
        return "limited"
    if "not allowed to run sudo" in text or not text.strip():
        return "no"
    return "limited"


def readable_secrets(pid: int, paths: list[str]) -> list[str]:
    """Of the configured secret paths, which can the process's user actually read (effective uid check)."""
    hits = []
    st = _status(pid)
    try:
        uid = int(st.get("Uid", "").split()[0])
    except (ValueError, IndexError):
        return hits
    is_root = (uid == 0)
    for p in paths:
        if not os.path.exists(p):
            continue
        if is_root:
            hits.append(p)
            continue
        # non-root: approximate with an access check from our own context only if we share the uid
        if os.geteuid() == uid and os.access(p, os.R_OK):
            hits.append(p)
        elif _world_or_group_readable(p):
            hits.append(p)
    return hits


def _world_or_group_readable(path: str) -> bool:
    try:
        mode = os.stat(path).st_mode
        return bool(mode & 0o044)
    except OSError:
        return False


def snapshot(pid: int, user: str, secret_paths: list[str]) -> dict:
    """The full per-agent permissions snapshot for one representative pid."""
    caps = capabilities(pid)
    return {
        "identity": identity(pid),
        "caps": caps,
        "high_risk_caps": sorted(set(caps) & _HIGH_RISK),
        "sudo": sudo_nopasswd(user),
        "readable_secrets": readable_secrets(pid, secret_paths),
    }
