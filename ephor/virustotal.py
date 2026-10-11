"""Optional VirusTotal enrichment — OFF by default, and the one place Ephor can talk to a third party.

Ephor's promise is that nothing about your machine leaves it: the default threat feeds are downloaded *to* you
and matched locally. VirusTotal is the opposite direction — to check a destination or a file hash you must
*send it to Google/VirusTotal*. That is a real privacy trade-off, so this module does nothing unless you
explicitly turn it on (config `[virustotal] enabled = true` with an `api_key`, or the `VT_API_KEY` env var,
plus `--virustotal` on the command).

When on, it *enriches* the free-feed verdict; it never replaces it. The free feeds keep working with no key,
offline. VT is only consulted for destinations the free feeds didn't already flag (no point spending quota
confirming a known-bad), and results are cached so the same destination isn't re-queried.

Free-tier limits (4 requests/minute, 500/day) are respected with a persisted counter and a minimum spacing
between calls; when the budget is exhausted, or the key is missing, or VT is unreachable, enrichment fails
soft — you get the free-feed verdict and Ephor never crashes.

Implemented with the standard library only (urllib), so enabling VT adds no dependency.
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.request
from pathlib import Path

from . import config

_API = "https://www.virustotal.com/api/v3"
_MIN_INTERVAL = 16.0  # seconds between calls -> <= ~4/min
_DAILY_CAP = 500
_CACHE_TTL = 7 * 86400  # a VT verdict is good for a week


def enabled(flag: bool = False) -> bool:
    """True only if the user opted in (flag or config) AND a key is resolvable."""
    conf = config.CONF.get("virustotal") or {}
    want = flag or bool(conf.get("enabled"))
    return want and bool(api_key())


def api_key() -> str:
    conf = config.CONF.get("virustotal") or {}
    return os.environ.get("VT_API_KEY") or conf.get("api_key") or ""


def _state_path() -> Path:
    return config.data_dir() / "vt_state.json"


def _cache_path() -> Path:
    return config.data_dir() / "vt_cache.json"


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _save(path: Path, data: dict) -> None:
    try:
        path.write_text(json.dumps(data))
    except OSError:
        pass


class VirusTotal:
    """Thin, polite VT v3 client. Construct once per run; it carries the rate-limit budget and caches."""

    def __init__(self, key: str = "") -> None:
        self.key = key or api_key()
        self.cache = _load(_cache_path())
        self.state = _load(_state_path())
        self._today = time.strftime("%Y-%m-%d")
        if self.state.get("day") != self._today:
            self.state = {"day": self._today, "count": 0, "last": 0.0}
        self.warned = False

    # -- budget -------------------------------------------------------------
    def _budget_left(self) -> bool:
        return self.state.get("count", 0) < _DAILY_CAP

    def _ready(self) -> bool:
        # non-blocking throttle: if we called too recently, skip this lookup rather than stall `watch`.
        # On a per-minute timer this naturally settles well under VT's 4/min free-tier limit.
        return (time.time() - self.state.get("last", 0.0)) >= _MIN_INTERVAL

    def _spend(self) -> None:
        self.state["count"] = self.state.get("count", 0) + 1
        self.state["last"] = time.time()
        _save(_state_path(), self.state)

    # -- cache --------------------------------------------------------------
    def _cached(self, ind: str):
        row = self.cache.get(ind)
        if row and (time.time() - row.get("ts", 0)) < _CACHE_TTL:
            return row
        return None

    def _store(self, ind: str, malicious: int, suspicious: int, source: str) -> dict:
        row = {"malicious": malicious, "suspicious": suspicious, "source": source, "ts": int(time.time())}
        self.cache[ind] = row
        _save(_cache_path(), self.cache)
        return row

    # -- queries ------------------------------------------------------------
    def _get(self, path: str) -> dict | None:
        if not self.key or not self._budget_left() or not self._ready():
            return None
        req = urllib.request.Request(f"{_API}{path}", headers={"x-apikey": self.key, "User-Agent": "ephor/0.1"})
        try:
            self._spend()
            with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 (fixed VT host)
                return json.loads(r.read().decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001 — fail soft: VT down/4xx/quota -> no enrichment
            return None

    @staticmethod
    def _verdict(stats: dict) -> tuple[int, int]:
        return int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))

    def check_destination(self, ip: str = "", domain: str = "") -> dict | None:
        """Return {'malicious','suspicious','source','ts'} or None. Cached; respects budget."""
        ind = domain or ip
        if not ind:
            return None
        hit = self._cached(ind)
        if hit is not None:
            return hit
        if domain:
            data = self._get(f"/domains/{domain}")
        else:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return None
            data = self._get(f"/ip_addresses/{ip}")
        if not data:
            return None
        stats = (data.get("data", {}).get("attributes", {}).get("last_analysis_stats") or {})
        mal, susp = self._verdict(stats)
        return self._store(ind, mal, susp, "virustotal")

    def check_hash(self, sha256: str) -> dict | None:
        """Look up a file hash: did an agent pull known malware? Cached; respects budget."""
        if not sha256:
            return None
        hit = self._cached(sha256)
        if hit is not None:
            return hit
        data = self._get(f"/files/{sha256}")
        if not data:
            return None
        stats = (data.get("data", {}).get("attributes", {}).get("last_analysis_stats") or {})
        mal, susp = self._verdict(stats)
        return self._store(sha256, mal, susp, "virustotal")

    @property
    def budget(self) -> dict:
        return {"used_today": self.state.get("count", 0), "cap": _DAILY_CAP, "left": max(0, _DAILY_CAP - self.state.get("count", 0))}


PRIVACY_WARNING = (
    "ephor: VirusTotal enrichment is ON — destinations and file hashes are being sent to a third party "
    "(VirusTotal/Google). Disable it to keep everything on this box."
)
