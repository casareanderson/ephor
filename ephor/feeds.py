"""Known-bad destination feeds — fetched once, cached on disk, matched offline.

Ephor is detect-only, so this is the whole of its "is this dangerous" judgement: does the IP or domain an
agent connected to appear on a public block/abuse feed? The feeds are standard, free, and well-regarded:

  urlhaus   abuse.ch URLhaus         malware-distribution hosts (domains + IPs)
  feodo     abuse.ch Feodo Tracker   botnet C2 IPs (Emotet/Dridex/etc.)
  firehol   FireHOL level1           aggregated attack/abuse IP ranges
  threatfox abuse.ch ThreatFox       IOC IPs (off by default; broader, noisier)

Each feed is downloaded at most once per `feed_ttl_hours`, parsed to a flat set, and cached as a plain text
file under the data dir. If the network is down or a feed 500s, Ephor falls back to the last good cache and
keeps working — a monitor that dies when abuse.ch has a bad day is no monitor at all.
"""
from __future__ import annotations

import ipaddress
import json
import time
import urllib.request
from pathlib import Path

from . import config

FEEDS = {
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "firehol": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "threatfox": "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
}

_UA = "ephor/0.1 (+https://github.com/)"


def _cache(name: str) -> Path:
    return config.data_dir() / f"feed_{name}.txt"


def _meta() -> Path:
    return config.data_dir() / "feed_meta.json"


def _fresh(name: str, ttl_h: int) -> bool:
    p = _cache(name)
    return p.is_file() and (time.time() - p.stat().st_mtime) < ttl_h * 3600


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (fixed https feed URLs)
        return r.read().decode("utf-8", "replace")


def _domain_and_ip_from_urlhaus(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = line.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        if host:
            out.add(host.lower())
    return out


def _ips(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith('"'):
            continue
        tok = line.split(",")[0].strip('" ') if "," in line else line.split()[0]
        try:
            ipaddress.ip_address(tok)
            out.add(tok)
        except ValueError:
            continue
    return out


def _netsets(text: str) -> list:
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return nets


def refresh(force: bool = False) -> dict:
    """Fetch any stale enabled feeds. Returns {feed: ('fetched'|'cached'|'offline', count)}."""
    ttl = config.feed_ttl_hours()
    status = {}
    meta = {}
    if _meta().is_file():
        try:
            meta = json.loads(_meta().read_text())
        except (OSError, json.JSONDecodeError):
            meta = {}
    for name, enabled in config.feeds_enabled().items():
        if not enabled:
            continue
        if not force and _fresh(name, ttl):
            status[name] = ("cached", meta.get(name, 0))
            continue
        try:
            text = _fetch(FEEDS[name])
            _cache(name).write_text(text)
            count = len(text.splitlines())
            meta[name] = count
            status[name] = ("fetched", count)
        except Exception:  # noqa: BLE001 — any failure falls back to cache
            status[name] = ("offline", meta.get(name, 0)) if _cache(name).is_file() else ("unavailable", 0)
    try:
        _meta().write_text(json.dumps(meta))
    except OSError:
        pass
    return status


class Matcher:
    """Loads whatever feed caches exist and answers is-this-bad for an IP or a domain."""

    def __init__(self) -> None:
        self.bad_ips: set[str] = set()
        self.bad_domains: set[str] = set()
        self.bad_nets: list = []
        self.sources: dict[str, str] = {}  # indicator -> feed name
        self._load()

    def _load(self) -> None:
        for name, enabled in config.feeds_enabled().items():
            if not enabled or not _cache(name).is_file():
                continue
            text = _cache(name).read_text()
            if name == "urlhaus":
                for d in _domain_and_ip_from_urlhaus(text):
                    (self.bad_ips if _is_ip(d) else self.bad_domains).add(d)
                    self.sources[d] = name
            elif name == "firehol":
                for net in _netsets(text):
                    self.bad_nets.append((net, name))
            else:  # feodo, threatfox -> IP lists
                for ip in _ips(text):
                    self.bad_ips.add(ip)
                    self.sources.setdefault(ip, name)

    def check(self, ip: str = "", domain: str = "") -> tuple[bool, str, str]:
        """Return (is_bad, indicator, feed)."""
        if domain:
            d = domain.lower().rstrip(".")
            if d in self.bad_domains:
                return True, d, self.sources.get(d, "feed")
            # match parent domains too (sub.bad.com hits bad.com)
            parts = d.split(".")
            for i in range(1, len(parts) - 1):
                parent = ".".join(parts[i:])
                if parent in self.bad_domains:
                    return True, parent, self.sources.get(parent, "feed")
        if ip:
            if ip in self.bad_ips:
                return True, ip, self.sources.get(ip, "feed")
            try:
                addr = ipaddress.ip_address(ip)
                for net, name in self.bad_nets:
                    if addr in net:
                        return True, str(net), name
            except ValueError:
                pass
        return False, "", ""

    def total(self) -> int:
        return len(self.bad_ips) + len(self.bad_domains) + len(self.bad_nets)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
