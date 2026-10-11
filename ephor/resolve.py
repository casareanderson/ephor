"""Best-effort reverse DNS, cached in-process.

Passive socket inspection gives an IP, not the hostname the agent asked for (that lived in a DNS query or TLS
SNI we deliberately don't capture). A reverse-DNS lookup is an imperfect but cheap way to put a human-readable
destination next to the IP and to give the domain feeds something to match. It is best-effort by design:
lookups are capped by a short timeout, failures fall back to the bare IP, and results are memoised so a busy
agent hitting one CDN doesn't trigger a lookup per sample.
"""
from __future__ import annotations

import socket

_cache: dict[str, str] = {}


def ptr(ip: str, timeout: float = 1.0) -> str:
    """Return a hostname for ip, or the ip itself if it can't be resolved."""
    if ip in _cache:
        return _cache[ip]
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        host = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
    except (OSError, socket.herror, socket.gaierror):
        host = ip
    finally:
        socket.setdefaulttimeout(old)
    _cache[ip] = host
    return host
