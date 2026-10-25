"""Real-time anomaly watch — the v0.2 headline feature.

`ephor watch --loop` re-samples on an interval and fires an alert the moment an agent does something new or
dangerous: a large transfer to a host it has never used, a connection to a known-bad destination, or an
unusual port. It is opt-in: without `--loop`, Ephor stays a one-shot tool with no resident loop.

The constraints are the same as the rest of Ephor — stdlib only, fully passive (reads only `ss`/`/proc`,
never blocks or kills), and light enough for a Pi. Each alert carries the originating host (box/CT), the
client binary read from `/proc` (`curl`, headless `chromium`/Playwright/Puppeteer, python `requests`, `node`,
…), and a destination category. Crawl/scrape clients are classified as their own `crawler:*` type, and known
crawl/scrape SaaS endpoints (e.g. Firecrawl) are labelled as a `crawl-saas` destination category.

The on-the-wire HTTP User-Agent is deliberately out of scope: it lives inside TLS, and reading it would need
a proxy that breaks Ephor's passive premise.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request
from dataclasses import dataclass, field

from . import collect, config, feeds, resolve, store, supply

try:
    import syslog
except ImportError:  # non-POSIX — won't happen on Linux, but stay safe
    syslog = None

# --- client classification -------------------------------------------------

# Client runtimes that are, by definition, crawlers/scrapers. Their connections come from a browser engine
# (Playwright/Puppeteer drive headless chromium) or a scraping framework, so they get their own `crawler:*`
# type rather than collapsing into `node`/`python`.
_CRAWLER_FRAMEWORKS = ("playwright", "puppeteer", "crawl4ai", "crawlee", "scrapy", "selenium")


def client_binary(exe: str, cmd: str) -> str:
    """Classify the client binary from ``/proc/<pid>/exe`` (+ cmdline). Crawlers are their own type."""
    cmd = (cmd or "").lower()
    base = os.path.basename(exe or "").lower()
    for kw in _CRAWLER_FRAMEWORKS:
        if kw in cmd or kw in base:
            return f"crawler:{kw}"
    if "chrom" in base:  # chromium / chrome / google-chrome / headless-shell
        return "crawler:chromium" if "--headless" in cmd else "chromium"
    if base == "curl":
        return "curl"
    if base == "wget":
        return "wget"
    if "python" in base:
        return "python-requests" if ("requests" in cmd or "urllib" in cmd or "httpx" in cmd) else "python"
    if base in ("node", "nodejs"):
        return "node"
    if base in ("firefox", "librewolf"):
        return "firefox"
    return base or "unknown"


def is_crawler(client: str) -> bool:
    return client.startswith("crawler:")


# --- destination category --------------------------------------------------

# Known hosted crawl/scrape SaaS endpoints. Calling one of these shows only the call and the bytes returned —
# the pages the service fetched happen off-box and are invisible to a passive host-side monitor.
_CRAWL_SAAS_SUFFIXES = (
    "firecrawl.dev",
    "firecrawl.com",
    "apify.com",
    "scrapingbee.com",
    "scraperapi.com",
    "brightdata.com",
    "zenrows.com",
    "scrapingdog.com",
)


def dest_category(dest: str) -> str:
    """Label a destination as ``crawl-saas`` when it is a known hosted crawl/scrape API. Empty otherwise."""
    d = (dest or "").lower().rstrip(".")
    for suf in _CRAWL_SAAS_SUFFIXES:
        if d == suf or d.endswith("." + suf):
            return "crawl-saas"
    return ""


# --- per-agent baseline ----------------------------------------------------

@dataclass
class Baseline:
    """Per-agent sets of 'normal' destinations and ports, seeded from the SQLite history and grown in memory."""

    dests: dict[str, set[str]] = field(default_factory=dict)
    ports: dict[str, set[int]] = field(default_factory=dict)

    @classmethod
    def load(cls, db) -> Baseline:
        b = cls()
        for agent, dest, port in store.baseline(db):
            b.dests.setdefault(agent, set()).add(dest)
            b.ports.setdefault(agent, set()).add(port)
        return b

    def knows_dest(self, agent: str, dest: str) -> bool:
        return dest in self.dests.get(agent, ())

    def knows_port(self, agent: str, port: int) -> bool:
        return port in self.ports.get(agent, ())

    def learn(self, agent: str, dest: str, port: int) -> None:
        self.dests.setdefault(agent, set()).add(dest)
        self.ports.setdefault(agent, set()).add(port)


# --- anomaly detection -----------------------------------------------------

KNOWN_BAD = "known_bad"
NEW_DESTINATION = "new_destination"
UNUSUAL_PORT = "unusual_port"


def analyze(*, agent: str, dest: str, ip: str, port: int, bytes_recv: int,
            is_bad: bool, indicator: str, feed: str,
            baseline: Baseline, large_transfer_bytes: int) -> str | None:
    """Return an anomaly reason for one connection, or None if it is normal. Pure — no I/O.

    Known-bad always fires (dangerous, regardless of baseline). Otherwise a port the agent has never used is
    'unusual', and a destination the agent has never used only fires once the transfer is large enough — a
    quiet box that keeps to its usual destinations and ports stays quiet.
    """
    if is_bad:
        return KNOWN_BAD
    if not baseline.knows_port(agent, port):
        return UNUSUAL_PORT
    if not baseline.knows_dest(agent, dest) and bytes_recv >= large_transfer_bytes:
        return NEW_DESTINATION
    return None


def gate(reason: str | None, in_warmup: bool) -> bool:
    """Should this reason be emitted right now? Known-bad (and the supply-chain alerts that are dangerous on
    their own: malware, curl | sh, a lookalike name) fire immediately; baseline anomalies wait out the warm-up
    window so the box's normal startup traffic is learned quietly."""
    return bool(reason) and (reason == KNOWN_BAD or reason in supply.IMMEDIATE or not in_warmup)


# --- alert + sinks ---------------------------------------------------------

@dataclass
class Alert:
    ts: int
    host: str
    container: str
    agent: str
    client: str
    crawler: bool
    dest: str
    ip: str
    port: int
    bytes_recv: int
    reason: str
    category: str = ""
    indicator: str = ""
    feed: str = ""
    via: str = ""
    detail: str = ""
    cmd: str = ""          # the command line that opened the connection (the "tool call")

    def as_dict(self) -> dict:
        return {
            "ts": self.ts, "host": self.host, "container": self.container,
            "agent": self.agent, "via": self.via, "client": self.client, "crawler": self.crawler,
            "dest": self.dest, "ip": self.ip, "port": self.port,
            "bytes_recv": self.bytes_recv, "reason": self.reason,
            "category": self.category, "indicator": self.indicator, "feed": self.feed, "detail": self.detail,
            "cmd": self.cmd,
        }


def format_line(a: Alert) -> str:
    who = a.host + (f"/{a.container}" if a.container else "")
    via = f" via {a.via}" if a.via else ""
    if not a.ip:                                   # supply-chain alerts: a command, a package or a name
        return f"ephor: {a.reason.upper()} {who} {a.agent}{via} -> {a.dest}" + (f" ({a.detail})" if a.detail else "")
    cat = f" [{a.category}]" if a.category else ""
    extra = f" ({a.feed}:{a.indicator})" if a.feed else ""
    cmd = f" | {a.cmd[:160]}" if a.cmd else ""
    return (f"ephor: {a.reason.upper()} {who} {a.agent}{via} ({a.client}"
            f"{', crawler' if a.crawler else ''}) -> {a.dest}:{a.port}{cat}"
            f" {a.bytes_recv} bytes{extra}{cmd}")


class StdoutSink:
    def send(self, a: Alert) -> None:
        print(format_line(a), flush=True)


class SyslogSink:
    def send(self, a: Alert) -> None:
        if syslog is None:
            return
        try:
            syslog.openlog("ephor")
            syslog.syslog(syslog.LOG_WARNING, format_line(a))
        except (OSError, AttributeError):
            pass  # syslog unavailable -> fail soft, never take the loop down


class WebhookSink:
    def __init__(self, url: str, fmt: str = "") -> None:
        if not url.lower().startswith(("https://", "http://")):
            raise ValueError(f"webhook must be an http(s) URL, got {url[:40]!r}")
        self.url = url
        self.fmt = fmt.lower()

    def _payload(self, a: Alert) -> bytes:
        text = format_line(a)
        # SIEM/Grafana: loki = Grafana Loki push API; the default (no recognised host) is the plain JSON
        # event most SIEMs ingest directly. Set --webhook-format to override the URL sniffing.
        if self.fmt == "loki" or (not self.fmt and "loki" in self.url):
            body = {"streams": [{"stream": {"ephor_reason": a.reason, "agent": a.agent, "host": a.host},
                                 "values": [[str(a.ts * 1_000_000_000), text]]}]}
        elif self.fmt == "discord" or (not self.fmt and "discord" in self.url):
            body = {"content": text, "username": "ephor"}
        elif self.fmt == "slack" or (not self.fmt and "slack" in self.url):
            body = {"text": text}
        else:
            body = a.as_dict()
        return json.dumps(body).encode("utf-8")

    def send(self, a: Alert) -> None:
        body = self._payload(a)
        hdrs = {"Content-Type": "application/json"}
        req = urllib.request.Request(self.url, data=body, headers=hdrs)  # noqa: S310 - http(s) only, see __init__
        try:
            with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 - http(s) only, see __init__
                r.read()
        except Exception as e:  # noqa: BLE001 — a webhook must never take the watch loop down
            print(f"ephor: webhook send failed: {type(e).__name__}: {str(e)[:120]}", file=sys.stderr)


def block_ip(ip: str, reason: str = "") -> str:
    """Opt-in enforcement: add an nftables drop rule for one address, with `reason` as an nft `comment` so
    every rule on the firewall is self-explanatory. Returns what happened (never raises). Detect-only by
    default — this only runs when `--block` is passed and nft + root are present."""
    import shutil as _sh, subprocess as _sp
    if not _sh.which("nft"):
        return "nft not installed (not blocked)"
    rule = ["nft", "add", "rule", "inet", "filter", "ephor-block", "ip", "saddr", ip, "drop"]
    if reason:
        # nft's comment statement takes a single bare token (spaces and colons are a syntax error), so sanitise.
        comment = "ephor-" + re.sub(r"[^A-Za-z0-9_.-]+", "-", reason[:120]).strip(".-")
        rule += ["comment", comment]
    p = _sp.run(rule, capture_output=True, text=True, timeout=30)
    if p.returncode == 0:
        return "blocked (nftables)"
    # table/chain may not exist yet — create them, then retry the rule once
    _sp.run(["nft", "add", "table", "inet", "filter"], capture_output=True, timeout=30)
    _sp.run(["nft", "add", "chain", "inet", "filter", "ephor-block", "{ type filter hook output priority 0 ; }"],
            capture_output=True, text=True, timeout=30)
    p = _sp.run(rule, capture_output=True, text=True, timeout=30)
    return "blocked (nftables)" if p.returncode == 0 else f"block failed: {(p.stderr or '').strip()[-120:]}"


def make_sinks(webhook: str = "", use_syslog: bool = False, fmt: str = "") -> list:
    sinks: list = [StdoutSink()]
    if webhook:
        try:
            sinks.append(WebhookSink(webhook, fmt))
        except ValueError as e:
            raise SystemExit(f"ephor: {e}") from None
    if use_syslog:
        sinks.append(SyslogSink())
    return sinks


# --- the loop --------------------------------------------------------------

def run_loop(args) -> int:
    """Continuously re-sample and alert. Opt-in: only reached when `--loop` is passed."""
    interval = max(1, int(args.interval))
    conf = config.alert()
    warmup_seconds = int(conf["warmup_seconds"])
    large_bytes = int(conf["large_transfer_bytes"])
    webhook = args.webhook or conf["webhook"] or ""
    use_syslog = bool(args.syslog or conf["syslog"])
    webhook_fmt = getattr(args, "webhook_format", "") or ""
    sinks = make_sinks(webhook, use_syslog, webhook_fmt)

    matcher = None if args.no_feeds else feeds.Matcher()
    block_enabled = bool(getattr(args, "block", False))
    if block_enabled and os.geteuid() != 0:
        print("ephor: --block needs root; running detect-only", file=sys.stderr)
        block_enabled = False
    db = store.connect()
    baseline = Baseline.load(db)
    alerted: set[tuple] = set()
    start = time.time()
    host = os.uname().nodename
    now = int(time.time())
    in_warmup = True

    def emit(reason, *, agent, via="", container="", dest="", ip="", port=0, bytes_recv=0, client="",
             indicator="", feed="", detail="", cmd=""):
        if not gate(reason, in_warmup):
            return
        key = (reason, agent, dest, port)
        if key in alerted:
            return
        alerted.add(key)
        if not ip:
            store.record_alert(db, agent, dest, ip, reason, detail[:200], now)
        if block_enabled and reason == KNOWN_BAD and ip:
            why = (f"{feed}:{indicator}" if feed else reason).strip()
            print(f"ephor: {block_ip(ip, agent + ' ' + why)}: {ip} ({agent} · {why})", flush=True)
            store.record_block(db, agent, dest, ip, reason, feed, indicator, cmd, now)
        alert = Alert(ts=now, host=host, container=container, agent=agent, client=client,
                      crawler=is_crawler(client), dest=dest, ip=ip, port=port, bytes_recv=bytes_recv,
                      reason=reason, category=dest_category(dest), indicator=indicator, feed=feed, via=via,
                      detail=detail, cmd=cmd)
        for sink in sinks:
            sink.send(alert)

    def on_conn(agent, via, container, ip, port, bytes_recv, client, cmd=""):
        dest = resolve.ptr(ip) if args.resolve else ip
        is_bad, indicator, feed = (False, "", "")
        if matcher:
            is_bad, indicator, feed = matcher.check(ip=ip, domain=dest if args.resolve else "")
        store.record_agent(db, agent, now)
        store.record_conn(db, agent, dest, ip, port, now, bytes_recv, is_bad, feed)
        if is_bad:
            store.record_alert(db, agent, dest, ip, feed, indicator, now)
        reason = analyze(agent=agent, dest=dest, ip=ip, port=port, bytes_recv=bytes_recv, is_bad=is_bad,
                         indicator=indicator, feed=feed, baseline=baseline, large_transfer_bytes=large_bytes)
        baseline.learn(agent, dest, port)
        if reason:
            emit(reason, agent=agent, via=via, container=container, dest=dest, ip=ip, port=port,
                 bytes_recv=bytes_recv, client=client, indicator=indicator, feed=feed, cmd=cmd)

    extra = None
    if getattr(args, "ebpf", False) or int(getattr(args, "inventory_every", 0) or 0) > 0:
        if getattr(args, "ebpf", False):
            from . import probe
            why = probe.check()
            if why:
                print("ephor: --ebpf unavailable: " + "; ".join(why), file=sys.stderr)
                db.close()
                return 1
        extra = supply.Supply(ebpf=bool(getattr(args, "ebpf", False)),
                              inventory_every=int(getattr(args, "inventory_every", 0) or 0),
                              pkg_checks=not (args.no_feeds or getattr(args, "no_pkg_checks", False)),
                              use_sieve=bool(getattr(args, "sieve", False)), rdap=bool(getattr(args, "rdap", False)),
                              matcher=matcher, roots=getattr(args, "inventory_root", None) or ["/"])
    print(f"ephor: watching every {interval}s (warm-up {warmup_seconds}s)"
          + (", eBPF probe on" if extra and extra.stream else "")
          + (f", inventory every {extra.inventory_every}s" if extra and extra.inventory_every else "")
          + "; Ctrl-C to stop", file=sys.stderr)
    try:
        while True:
            s = collect.sample()
            now = int(time.time())
            in_warmup = (time.time() - start) < warmup_seconds
            if not s.have_ss and not (extra and extra.stream):
                print("ephor: 'ss' (iproute2) not found — cannot read the socket table", file=sys.stderr)
                time.sleep(interval)
                continue
            with db:
                for c in collect.attribute(s):
                    on_conn(c.agent, c.via, c.container, c.rip, c.rport, c.bytes_recv, client_binary(c.exe, c.cmd), c.cmd)
                if extra:
                    extra.handle_events(db, now, emit, on_conn)
                    if extra.inventory_due():
                        extra.inventory(db, now, emit)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nephor: watch stopped")
    finally:
        if extra:
            extra.stop()
        db.close()
    return 0
