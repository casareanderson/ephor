"""`ephor dns-proxy`: see every DNS name, and who asked, on a box without eBPF. Opt-in.

A tiny stdlib UDP forwarder. Point the box's resolver at it (for example `nameserver 127.0.0.1` with
`--listen 127.0.0.1:53`, or a systemd-resolved `DNS=127.0.0.1:5353`), and it passes every query on to the real
upstream unchanged while noting the name. It finds the asking process from the query's source port
(`/proc/net/udp` -> socket inode -> the process holding that socket), so each name is tied to an agent, then runs
the same checks as the eBPF probe.

It is the one part of Ephor that sits in the path of traffic, which is why it is a separate, opt-in command:
it never rewrites or drops an answer, and if Ephor stops, point the resolver back. UDP only (TCP DNS and
DNS-over-HTTPS go straight past it; a DoH endpoint still shows up in `watch` as a connection).
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import threading


def qname(packet: bytes) -> str:
    """The first question's name from a DNS query, or '' if it can't be read."""
    try:
        i, labels = 12, []
        while True:
            n = packet[i]
            if n == 0:
                break
            if n & 0xC0:                       # a pointer in a question is unusual; stop rather than follow it
                return ""
            labels.append(packet[i + 1:i + 1 + n].decode("ascii", "replace"))
            i += 1 + n
            if len(labels) > 127:
                return ""
        return ".".join(labels).lower()
    except IndexError:
        return ""


def upstream_from_resolv(path: str = "/etc/resolv.conf", skip: tuple = ("127.0.0.1", "::1")) -> str:
    try:
        with open(path) as f:
            for line in f:
                p = line.split()
                if len(p) >= 2 and p[0] == "nameserver" and p[1] not in skip and not p[1].startswith("127."):
                    return p[1]
    except OSError:
        pass
    return "1.1.1.1"


def _inode_for_port(port: int, proc: str = "/proc") -> str:
    for table in ("net/udp", "net/udp6"):
        try:
            with open(f"{proc}/{table}") as f:
                next(f)
                for line in f:
                    p = line.split()
                    if len(p) > 9 and int(p[1].rsplit(":", 1)[1], 16) == port:
                        return p[9]
        except (OSError, ValueError, StopIteration):
            continue
    return ""


def _pid_for_inode(inode: str, proc: str = "/proc") -> int:
    want = f"socket:[{inode}]"
    for d in os.listdir(proc):
        if not d.isdigit():
            continue
        try:
            for fd in os.listdir(f"{proc}/{d}/fd"):
                try:
                    if os.readlink(f"{proc}/{d}/fd/{fd}") == want:
                        return int(d)
                except OSError:
                    continue
        except OSError:
            continue
    return 0


def pid_for_source_port(port: int, proc: str = "/proc") -> int:
    inode = _inode_for_port(port, proc)
    return _pid_for_inode(inode, proc) if inode and inode != "0" else 0


def serve(listen: str, upstream: str, on_query, timeout: float = 4.0) -> None:
    """Forward forever. on_query(pid, name) is called for every query (in a worker thread)."""
    host, _, port = listen.rpartition(":")
    fam = socket.AF_INET6 if ":" in host.strip("[]") else socket.AF_INET
    srv = socket.socket(fam, socket.SOCK_DGRAM)
    srv.bind((host.strip("[]") or "127.0.0.1", int(port or 53)))
    up = (upstream, 53)
    up_fam = socket.AF_INET6 if ":" in upstream else socket.AF_INET

    def handle(data: bytes, addr) -> None:
        name = qname(data)
        pid = pid_for_source_port(addr[1]) if addr[0] in ("127.0.0.1", "::1") else 0
        try:
            with socket.socket(up_fam, socket.SOCK_DGRAM) as u:
                u.settimeout(timeout)
                u.sendto(data, up)
                reply, _ = u.recvfrom(65535)
            srv.sendto(reply, addr)
        except OSError:
            pass                               # no answer: the client retries or times out as it would anyway
        if name:
            try:
                on_query(pid, name)
            except Exception as e:  # noqa: BLE001 - noting a name must never break resolution
                print(f"ephor: dns-proxy could not record {name}: {type(e).__name__}: {e}", file=sys.stderr)

    while True:
        data, addr = srv.recvfrom(65535)
        if len(data) >= 12 and not (struct.unpack("!H", data[2:4])[0] & 0x8000):     # queries only
            threading.Thread(target=handle, args=(data, addr), daemon=True).start()
