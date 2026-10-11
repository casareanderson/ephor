"""Passively read the current outbound connections and attribute each to an agent.

No proxy, no packet capture, no kernel module. Ephor asks the kernel what is *already* connected
(`ss -tnp state established`) and reads `/proc/<pid>/{cmdline,exe,status,cgroup}` for the owning process.
Because it reads the socket table, it sees every connection regardless of how the agent was told to route —
there is nothing for an agent to opt out of or bypass. The trade-off is honest: it samples point-in-time
state, so a connection that opens and closes entirely between two samples can be missed. Run `watch` on a
short interval for near-complete coverage.

`ss -i` also reports bytes received per socket, which is how Ephor tells "pinged a URL" from "pulled down a
200 MB file" without inspecting any traffic.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field

from . import classify


@dataclass
class Conn:
    pid: int
    rip: str
    rport: int
    bytes_recv: int = 0


@dataclass
class Sample:
    ts: int
    host: str
    is_root: bool
    have_ss: bool
    conns: list[Conn] = field(default_factory=list)
    # pid -> (uid, cmdline, exe, cgroup)
    procs: dict[int, tuple[int, str, str, str]] = field(default_factory=dict)


@dataclass
class AgentConn:
    agent: str
    pid: int
    uid: int
    user: str
    exe: str
    cmd: str
    rip: str
    rport: int
    bytes_recv: int
    container: str = ""


# The peer endpoint is the addr:port immediately before `users:(`. Anchoring here is robust whether or not
# `ss` printed the State column (it omits it when the command already filters by state).
_SOCK = re.compile(r"(\[[0-9a-fA-F:]+\]|[0-9.]+):(\d+)\s+users:\(")
_PID = re.compile(r"pid=(\d+)")
_BRECV = re.compile(r"bytes_received:(\d+)")


def _read(path: str) -> str:
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def _cmdline(pid: int) -> str:
    raw = _read(f"/proc/{pid}/cmdline")
    return raw.replace("\x00", " ").strip()


def _exe(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def _uid(pid: int) -> int:
    for line in _read(f"/proc/{pid}/status").splitlines():
        if line.startswith("Uid:"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return -1
    return -1


def _cgroup(pid: int) -> str:
    return _read(f"/proc/{pid}/cgroup").strip().splitlines()[-1] if _read(f"/proc/{pid}/cgroup") else ""


def username(uid: int) -> str:
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError, OverflowError):
        return str(uid)


def container_of(pid: int, cgroup: str) -> str:
    """Best-effort container id/name from cgroup or /proc/<pid>/root. Empty string if host-native."""
    m = re.search(r"(docker|libpod|containerd)[-/]([0-9a-f]{12,64})", cgroup)
    if m:
        return m.group(2)[:12]
    m = re.search(r"/lxc(?:\.payload)?[./]([^/]+)", cgroup)
    if m:
        return "lxc:" + m.group(1)
    m = re.search(r"machine-([^.]+)\.scope", cgroup)
    if m:
        return m.group(1)
    return ""


def is_internet(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def parse_ss(out: str, internet_only: bool = True) -> list[Conn]:
    """Parse `ss -tnpiH` output into Conn rows. `ss -i` prints a socket line then an indented info line."""
    lines = out.splitlines()
    conns: list[Conn] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        sm = _SOCK.search(line)
        if not sm:
            i += 1
            continue
        rip = sm.group(1).strip("[]")
        rport = int(sm.group(2))
        pm = _PID.search(line)
        info = lines[i + 1] if i + 1 < len(lines) and lines[i + 1][:1] in (" ", "\t") else ""
        brecv = int(_BRECV.search(info).group(1)) if _BRECV.search(info) else 0
        i += 2 if info else 1
        if not pm:
            continue
        if internet_only and not is_internet(rip):
            continue
        conns.append(Conn(pid=int(pm.group(1)), rip=rip, rport=rport, bytes_recv=brecv))
    return conns


def sample() -> Sample:
    """Take one point-in-time sample of established outbound connections, attributed to processes."""
    s = Sample(ts=int(time.time()), host=os.uname().nodename, is_root=(os.geteuid() == 0), have_ss=bool(shutil.which("ss")))
    if not s.have_ss:
        return s
    try:
        out = subprocess.run(
            ["ss", "-tnpiH", "state", "established"],
            capture_output=True, text=True, timeout=15,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return s
    s.conns = parse_ss(out)
    for c in s.conns:
        if c.pid not in s.procs:
            s.procs[c.pid] = (_uid(c.pid), _cmdline(c.pid), _exe(c.pid), _cgroup(c.pid))
    return s


def attribute(s: Sample) -> list[AgentConn]:
    """Join connections to processes and classify the owner. Ignored processes are dropped."""
    out: list[AgentConn] = []
    for c in s.conns:
        p = s.procs.get(c.pid)
        if not p:
            continue
        uid, cmd, exe, cg = p
        if classify.ignored(cmd):
            continue
        out.append(AgentConn(
            agent=classify.classify(cmd, exe),
            pid=c.pid, uid=uid, user=username(uid), exe=exe, cmd=cmd,
            rip=c.rip, rport=c.rport, bytes_recv=c.bytes_recv,
            container=container_of(c.pid, cg),
        ))
    return out
