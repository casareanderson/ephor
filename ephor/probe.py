"""The eBPF bridge: kernel events for Ephor without giving up "stdlib only".

Sampling `ss` and `/proc` misses anything that starts and finishes between two samples: a `pip install`, a
`curl | sh`, a DNS lookup. eBPF sees those as they happen, but loading eBPF programs needs a compiler or libbpf,
which plain Python doesn't have. So Ephor doesn't load them itself: it writes a small bpftrace program, runs
`bpftrace` (one package on most distros) and reads its output line by line. bpftrace is optional; without it
Ephor works exactly as before.

What the program reports (all read-only; nothing is blocked, changed or written to by the probe):

  E  a process started: pid, parent pid, uid, cgroup, the command line read from the new process's memory
  D  a DNS lookup through libc `getaddrinfo`: pid and the name asked for. The probe attaches to the host's libc
     and to the libc inside each running container (an LXC or Docker container has its own copy)
  C  an outgoing TCP connection (SYN sent): pid, destination address and port, so even a sub-second connection
     is seen

Limits: names resolved without libc (Go's built-in resolver, some static binaries, DNS-over-HTTPS) don't show up
as D events; a DoH resolver still shows up as a C event to a known DoH endpoint. Needs root, a kernel with BTF
(`/sys/kernel/btf/vmlinux`, standard since about 5.8) and bpftrace 0.16 or newer. In an unprivileged container
eBPF isn't available: run Ephor's probe on the host, which sees every container's processes.
"""
from __future__ import annotations

import glob
import os
import queue
import shutil
import subprocess
import threading
from dataclasses import dataclass, field

ARG_BYTES = 240          # how much of each command line the kernel side copies


@dataclass
class Event:
    kind: str            # "exec" | "dns" | "connect"
    pid: int
    ppid: int = 0
    uid: int = -1
    comm: str = ""
    argv: list[str] = field(default_factory=list)
    name: str = ""       # dns
    ip: str = ""         # connect
    port: int = 0        # connect
    cgroup: str = ""     # e.g. unified:/lxc/100/ns/.lxc or /system.slice/docker-<id>.scope

    @property
    def cmd(self) -> str:
        return " ".join(self.argv)


def _unescape(s: str) -> list[str]:
    """bpftrace prints a buffer with %r as text with \\xNN escapes. Split the NUL-separated argv back out."""
    i, b = 0, bytearray()
    while i < len(s):
        if s[i] == "\\" and i + 3 < len(s) and s[i + 1] == "x":
            try:
                b.append(int(s[i + 2:i + 4], 16))
                i += 4
                continue
            except ValueError:
                pass
        b += s[i].encode("utf-8", "replace")
        i += 1
    return [a.decode("utf-8", "replace") for a in bytes(b).split(b"\x00") if a]


def parse_line(line: str) -> Event | None:
    """One line of probe output -> Event, or None for anything else (banner, warnings)."""
    p = line.rstrip("\n").split("\t")
    try:
        if p[0] == "E" and len(p) >= 7:
            return Event("exec", int(p[1]), ppid=int(p[2]), uid=int(p[3]), comm=p[4], cgroup=p[5],
                         argv=_unescape(p[6]))
        if p[0] == "D" and len(p) >= 5:
            return Event("dns", int(p[1]), comm=p[2], cgroup=p[3], name=p[4].strip().rstrip(".").lower())
        if p[0] == "C" and len(p) >= 6:
            return Event("connect", int(p[1]), comm=p[2], cgroup=p[3], ip=p[4], port=int(p[5]))
    except (ValueError, IndexError):
        return None
    return None


def libcs(proc: str = "/proc") -> list[str]:
    """Distinct libc files to hook: the host's, plus each container's (found through /proc/<pid>/root).
    De-duplicated by inode, so a hundred processes in one container add one probe."""
    pats = ("lib/*/libc.so.6", "usr/lib/*/libc.so.6", "lib/libc.so.6", "lib/ld-musl-*.so.1")
    cands = [c for pat in pats for c in glob.glob("/" + pat)]
    roots, seen_roots = [], {_stat("/")}
    for d in glob.glob(f"{proc}/[0-9]*"):
        st = _stat(f"{d}/root")
        if st and st not in seen_roots:
            seen_roots.add(st)
            roots.append(f"{d}/root")
    for root in roots:
        cands += [c for pat in pats for c in glob.glob(f"{root}/{pat}")]
    out, seen = [], set()
    for c in cands:
        st = _stat(c)
        if st and st not in seen:
            seen.add(st)
            out.append(c)
    return out


def _stat(path: str):
    try:
        s = os.stat(path)
        return (s.st_dev, s.st_ino)
    except OSError:
        return None


def program(libc_paths: list[str]) -> str:
    """The bpftrace source. Kept small and readable on purpose: `ephor probe --print` shows it."""
    parts = [f"""
tracepoint:sched:sched_process_exec
{{
  $s = curtask->mm->arg_start;
  $n = curtask->mm->arg_end - $s;
  if ($n > {ARG_BYTES}) {{ $n = {ARG_BYTES}; }}
  printf("E\\t%d\\t%d\\t%d\\t%s\\t%s\\t%r\\n", pid, curtask->real_parent->tgid, uid, comm,
         cgroup_path(cgroup), buf(uptr($s), $n));
}}

tracepoint:sock:inet_sock_set_state
/args.newstate == 2 && args.family == 2/
{{
  printf("C\\t%d\\t%s\\t%s\\t%s\\t%d\\n", pid, comm, cgroup_path(cgroup), ntop(args.daddr), args.dport);
}}

tracepoint:sock:inet_sock_set_state
/args.newstate == 2 && args.family == 10/
{{
  printf("C\\t%d\\t%s\\t%s\\t%s\\t%d\\n", pid, comm, cgroup_path(cgroup), ntop(args.daddr_v6), args.dport);
}}
"""]
    if libc_paths:
        hooks = ",\n".join(f"uprobe:{p}:getaddrinfo" for p in libc_paths)
        parts.append(f"""
{hooks}
{{
  printf("D\\t%d\\t%s\\t%s\\t%s\\n", pid, comm, cgroup_path(cgroup), str(arg0));
}}
""")
    return "".join(parts)


def check() -> list[str]:
    """Why the probe can't run here ([] means it can)."""
    why = []
    if os.geteuid() != 0:
        why.append("needs root (eBPF programs can only be loaded by root)")
    if not shutil.which("bpftrace"):
        why.append("bpftrace is not installed (apt/dnf install bpftrace)")
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        why.append("kernel has no BTF (/sys/kernel/btf/vmlinux missing)")
    if os.path.exists("/proc/1/environ") and _in_unprivileged_container():
        why.append("this looks like an unprivileged container: run the probe on the host instead")
    return why


def _in_unprivileged_container() -> bool:
    try:
        with open("/proc/self/uid_map") as f:
            first = f.read().split()
        return len(first) >= 2 and first[1] != "0"
    except OSError:
        return False


class Stream:
    """Run bpftrace in the background and hand out parsed events. Bounded: if Ephor falls behind, the oldest
    events are dropped and counted rather than memory growing."""

    def __init__(self, libc_paths: list[str] | None = None, maxsize: int = 50000) -> None:
        self.q: queue.Queue[Event] = queue.Queue(maxsize=maxsize)
        self.dropped = 0
        self.src = program(libcs() if libc_paths is None else libc_paths)
        self.proc = subprocess.Popen(["bpftrace", "-q", "-B", "line", "-e", self.src],  # noqa: S607
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
                                     errors="replace")
        self.t = threading.Thread(target=self._pump, daemon=True)
        self.t.start()

    def _pump(self) -> None:
        for line in self.proc.stdout:
            ev = parse_line(line)
            if ev is None:
                continue
            try:
                self.q.put_nowait(ev)
            except queue.Full:
                self.dropped += 1

    def alive(self) -> bool:
        return self.proc.poll() is None

    def error(self) -> str:
        if self.alive():
            return ""
        return (self.proc.stderr.read() or "").strip()[-400:]

    def drain(self, limit: int = 20000) -> list[Event]:
        out = []
        while len(out) < limit:
            try:
                out.append(self.q.get_nowait())
            except queue.Empty:
                break
        return out

    def stop(self) -> None:
        if self.alive():
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
