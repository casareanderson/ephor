"""Is this DNS name worth a second look? Offline checks on the name an agent asked for.

Ephor gets the name from the eBPF probe (`getaddrinfo` in libc) or from `ephor dns-proxy`. Each check returns a
short reason; none of them needs the network, except the optional registration-age lookup (`young_domain`), which
asks RDAP and is off unless you pass `--rdap`.

  feed        the name is on a threat feed Ephor already downloads (URLhaus, ThreatFox)
  lookalike   it borrows the name of a package registry, code host or AI API without being it:
              pypi-org.com, files-pythonhosted.net, npmjs-registry.com, githubusercontent.io, pypj.org
  punycode    an internationalised (xn--) label: the classic way to make a name look like another
  random      a long label of random-looking letters and digits, the shape malware-generated domains have
  doh         a well-known DNS-over-HTTPS resolver: an agent using its own DoH skips the system resolver (and
              Ephor's DNS view); reported on the connection, see `doh_endpoint`

They are heuristics and say so. A `lookalike` hit on a name you use on purpose goes in `dns_allow` in the config.
"""
from __future__ import annotations

import json
import math
import time
import urllib.request

from . import config

# Registrable domains agents fetch code and models from. A name that contains one of these brands but isn't the
# domain itself (or a subdomain of it) is a lookalike.
PROTECTED = {
    "pypi.org": "pypi", "pythonhosted.org": "pythonhosted", "npmjs.org": "npmjs", "npmjs.com": "npmjs",
    "yarnpkg.com": "yarnpkg", "githubusercontent.com": "githubusercontent", "huggingface.co": "huggingface",
    "rubygems.org": "rubygems",
    # typo / embedding checks only: these brands also appear in plenty of legitimate names
    "github.com": "", "gitlab.com": "", "openai.com": "", "anthropic.com": "", "brew.sh": "", "crates.io": "",
    "golang.org": "", "docker.io": "", "docker.com": "", "ghcr.io": "", "debian.org": "", "ubuntu.com": "",
    "googleapis.com": "", "hf.co": "",
}
# Real services whose names contain a protected brand.
KNOWN_OK = {"pypistats.org"}
_TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.jp", "co.nz", "com.br", "co.in", "co.za"}

DOH = {"dns.google", "dns.google.com", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "one.one.one.one",
       "dns.quad9.net", "dns9.quad9.net", "doh.opendns.com", "dns.adguard-dns.com", "dns.nextdns.io",
       "doh.mullvad.net", "dns.controld.com"}
DOH_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222",
           "94.140.14.14", "2606:4700:4700::1111", "2001:4860:4860::8888"}


def registrable(name: str) -> str:
    """eTLD+1, the cheap way: last two labels, three for the common two-level public suffixes."""
    parts = name.lower().rstrip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _lev(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike(name: str) -> str:
    """The protected domain this name imitates, or ''."""
    n = name.lower().rstrip(".")
    reg = registrable(n)
    if reg in PROTECTED or reg in KNOWN_OK:
        return ""
    for real, brand in PROTECTED.items():
        if n == real or n.endswith("." + real):
            return ""
        # brand inside another registrable name: pypi-org.com, pypi.org.evil.io, githubusercontent.io
        if brand and len(brand) >= 4 and brand in reg.split(".")[0]:
            return real
        if n.startswith(real + ".") or ("." + real + ".") in ("." + n + "."):
            return real
        # one or two typos in the registrable part: pypj.org, npnjs.com, huggingface.cc
        if len(real) >= 7 and _lev(reg, real) <= (1 if len(real) < 10 else 2):
            return real
    return ""


def _entropy(s: str) -> float:
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s)) if s else 0.0


def random_looking(name: str) -> bool:
    """A label of 16+ chars that is high-entropy, mixes in digits and has few vowels. Deliberately conservative:
    CDN hash names (d1a2b3c4.cloudfront.net) are under known suffixes and skipped."""
    n = name.lower().rstrip(".")
    if registrable(n) in ("cloudfront.net", "amazonaws.com", "azureedge.net", "akamaiedge.net", "fastly.net",
                          "googleusercontent.com", "r2.dev", "workers.dev", "ngrok.io", "ngrok-free.app"):
        return False
    label = registrable(n).split(".")[0]
    if len(label) < 16:
        return False
    vowels = sum(c in "aeiou" for c in label) / len(label)
    digits = sum(c.isdigit() for c in label)
    return _entropy(label) > 3.6 and vowels < 0.3 and digits >= 2


def doh_endpoint(dest: str, port: int) -> bool:
    return port == 443 and (dest.lower().rstrip(".") in DOH or dest in DOH_IPS)


def allowed(name: str) -> bool:
    n = name.lower().rstrip(".")
    for a in config.CONF.get("dns_allow") or []:
        a = str(a).lower().rstrip(".")
        if n == a or n.endswith("." + a):
            return True
    return False


def check(name: str, matcher=None) -> list[tuple[str, str]]:
    """[(reason, detail)] for one DNS name. Empty means nothing to say."""
    n = (name or "").lower().rstrip(".")
    if not n or "." not in n or n.endswith((".local", ".lan", ".internal", ".arpa", ".home.arpa")) or allowed(n):
        return []
    out = []
    if matcher is not None:
        bad, indicator, feed = matcher.check(domain=n)
        if bad:
            out.append(("dns_feed", f"{feed}:{indicator}"))
    real = lookalike(n)
    if real:
        out.append(("dns_lookalike", f"looks like {real}"))
    if any(lbl.startswith("xn--") for lbl in n.split(".")):
        out.append(("dns_punycode", "internationalised name (xn--)"))
    if random_looking(n):
        out.append(("dns_random", "random-looking name"))
    return out


# ---------------------------------------------------------------- optional: registration age (network)

_RDAP = "https://rdap.org/domain/"
_rdap_cache: dict[str, tuple[float, int | None]] = {}


def young_domain(name: str, days: int = 30, timeout: float = 5.0) -> int | None:
    """Days since the registrable domain was registered, if that is under `days`; else None. Asks RDAP (opt-in,
    network), cached for a day. Any failure is None: an unknown age is not an alert."""
    reg = registrable(name)
    hit = _rdap_cache.get(reg)
    if hit and time.time() - hit[0] < 86400:
        age = hit[1]
    else:
        age = None
        try:
            req = urllib.request.Request(_RDAP + reg, headers={"Accept": "application/rdap+json",  # noqa: S310
                                                               "User-Agent": "ephor"})
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - fixed https RDAP host
                d = json.load(r)
            for ev in d.get("events", []):
                if ev.get("eventAction") == "registration":
                    t = time.mktime(time.strptime(ev["eventDate"][:10], "%Y-%m-%d"))
                    age = int((time.time() - t) // 86400)
        except Exception:  # noqa: BLE001 - RDAP is best effort
            age = None
        _rdap_cache[reg] = (time.time(), age)
    return age if age is not None and age < days else None
