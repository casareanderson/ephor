"""Is a package an agent just installed known-bad, or suspiciously new? (network, on by default with feeds)

  malicious   OSV.dev has a MAL-* advisory for it: OpenSSF's malicious-packages list (typosquats, credential
              stealers, packages that exist only to be "hallucinated" by AI models and then registered)
  young       first published under `young_days` days ago (default 30) on PyPI or npm. Most real dependencies are
              years old; a days-old package an agent picked is worth a look ("slopsquatting")
  sieve       optional: if sieve (https://github.com/casareanderson/sieve) is installed, run `sieve path` on the
              directory that changed and report new known-exploited or malicious findings

Every lookup is cached per (ecosystem, name, version) for a day, failures are silent (an unknown is not an alert),
and nothing is sent except the package name and version.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.parse
import urllib.request

_OSV = "https://api.osv.dev/v1/query"
_ECO = {"pypi": "PyPI", "pip": "PyPI", "uv": "PyPI", "pipx": "PyPI", "npm": "npm", "pnpm": "npm", "yarn": "npm",
        "bun": "npm", "cargo": "crates.io", "gem": "RubyGems", "go": "Go"}
_cache: dict[tuple, tuple[float, object]] = {}


def ecosystem(manager: str) -> str:
    return _ECO.get(manager, "")


def _get(url: str, data: bytes | None = None, timeout: float = 8.0):
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json",  # noqa: S310
                                                           "User-Agent": "ephor"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - fixed https hosts (OSV, PyPI, npm)
        return json.load(r)


def _cached(key: tuple, fn):
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < 86400:
        return hit[1]
    try:
        val = fn()
    except Exception:  # noqa: BLE001 - best effort, never an alert on failure
        val = None
    _cache[key] = (time.time(), val)
    return val


def malicious(eco: str, name: str, version: str = "") -> list[str]:
    """MAL-* advisory ids OSV has for this package (and version, if given)."""
    if not eco or not name:
        return []

    def ask():
        q = {"package": {"name": name, "ecosystem": eco}}
        if version:
            q["version"] = version
        d = _get(_OSV, json.dumps(q).encode())
        return [v["id"] for v in d.get("vulns", []) if v.get("id", "").startswith("MAL-")]
    return _cached(("mal", eco, name, version), ask) or []


def first_published_days(eco: str, name: str) -> int | None:
    """Days since the package's first release on PyPI or npm, or None if unknown."""
    def ask():
        if eco == "PyPI":
            d = _get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
            times = [f["upload_time_iso_8601"] for files in d.get("releases", {}).values() for f in files
                     if f.get("upload_time_iso_8601")]
            first = min(times) if times else None
        elif eco == "npm":
            d = _get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
            first = (d.get("time") or {}).get("created")
        else:
            return None
        if not first:
            return None
        t = time.mktime(time.strptime(first[:10], "%Y-%m-%d"))
        return int((time.time() - t) // 86400)
    return _cached(("age", eco, name), ask)


def check(manager: str, name: str, version: str = "", young_days: int = 30) -> list[tuple[str, str]]:
    """[(reason, detail)] for one installed package."""
    eco = ecosystem(manager)
    if not eco:
        return []
    out = []
    mal = malicious(eco, name, version)
    if mal:
        out.append(("malicious_package", ", ".join(mal[:3])))
    age = first_published_days(eco, name)
    if age is not None and age < young_days:
        out.append(("young_package", f"first published {age} day(s) ago"))
    return out


def sieve_path(directory: str, timeout: int = 300) -> tuple[int, int] | None:
    """(known-exploited, malicious) finding counts from `sieve path DIR --json`, or None if sieve isn't there or
    failed. sieve is optional; Ephor never installs it."""
    exe = shutil.which("sieve")
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "path", directory, "--json"], capture_output=True, text=True, timeout=timeout)
        d = json.loads(r.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    s = d.get("summary") or {}
    return int(s.get("kev", 0)), int(s.get("malicious", 0))
