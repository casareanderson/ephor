# Ephor

**Passive, detect-only monitoring of what AI agents do on a Linux box** — which agent went where, what it
downloaded, whether it touched a known-bad destination, and what each agent can actually access.

Ephor doesn't sit in your agents' traffic. It reads the kernel's own socket table (`ss`) and `/proc`, so it
sees **every** outbound connection an agent makes regardless of how that agent was configured to route — there
is no proxy to set up and nothing for an agent to opt out of or route around. It's **detect-only by design**:
it reports, it never blocks, kills, or firewalls anything.

Part of the [warden family](#the-warden-family): use it on its own, or alongside [warden](https://github.com/casareanderson/warden) and [sieve](https://github.com/casareanderson/sieve).

```
$ ephor agents
AGENT                    DESTS DOWNLOADED BAD  LAST SEEN
hermes:coder                14      112.4MB   0  2m ago
ollama                       3      1.9GB     0  2m ago
scraper                     38      8.1MB     1  1m ago
py:rss_fetch                 6      402.0KB   0  5m ago

$ ephor agent scraper --perms
== scraper: 38 destination(s) ==
DESTINATION                               PORT DOWNLOADED  SEEN  FLAG
203.0.113.61                              443      1.2KB     3  BAD:feodo
cdn.example.com                            443      6.8MB    40
...
== scraper: permissions (blast radius) ==
  runs as     : root (uid 0)  groups: root, docker
  sudo nopass : yes
  capabilities: net_raw, sys_admin        <- high-risk, shown in red
  can read    : /run/secrets, /root/.env
```

That last block is the part the egress tools skip. Knowing an agent *went* somewhere is half the question; the
other half is blast radius — **if this agent were prompt-injected or compromised, what could it touch?** Ephor
reads that straight from the kernel: the user it runs as, its Linux capabilities, passwordless `sudo`, and
which of your secret files it can actually read.

## Why Ephor

AI agents now run shell commands, call tools, and fetch URLs on your machines. Most of the tooling to watch
them is either an **inline proxy** you have to configure every agent to use (so it only sees the traffic that
cooperates, and a compromised agent can route around it) or a **heavy endpoint monitor** built for corporate
Windows fleets. Ephor is the small, honest, Linux-first option:

- **Passive — can't be bypassed.** Reads `/proc` + the socket table. No proxy, no `HTTP_PROXY` env var to set,
  no CA to install. Sees all egress, cooperating or not.
- **Dependency-free.** Pure Python standard library. No packages to install, no database server, no Go/Rust
  binary, no background daemon holding your traffic. `pip install ephor` and run.
- **Shows permissions, not just destinations.** The blast-radius view is unique to Ephor.
- **Real downloads, not just hits.** Uses per-socket `bytes_received`, so a 2 GB model pull looks different
  from a health-check ping.
- **Runs on tiny hardware.** See below — this is a real design goal, kept honest.

## Runs on tiny hardware (what that actually means)

Ephor is meant to run on the **smallest Linux hardware you have lying around**: a Raspberry Pi (including a Pi
Zero 2 W), an old thin client, a NAS, a mini-PC, or a router flashed with Entware/Python. If it runs Linux and
has Python 3.11+, it runs Ephor. There's no compiled component and no resident service — a scan is a short
Python process that samples, writes a few SQLite rows, and exits.

**What it does _not_ run on, and we won't pretend otherwise:** microcontroller boards like the ESP32/ESP8266,
Arduino, or similar. Those don't run Linux, have no processes or `/proc` to inspect, and no AI agent runs on
them — so there's nothing for Ephor to monitor there. A claim like "runs on an ESP32" would be false, and we'd
rather keep your trust.

> Roadmap idea (optional, not where the tool runs): an ESP board *could* make a nice cheap **hardware alert
> sink** — a light or buzzer that Ephor pings over the LAN when it sees a known-bad hit. That's an add-on
> output, separate from the Linux host doing the actual monitoring.

### Footprint

Measured on the reference box (a Proxmox LXC, Python 3.12; your Pi will be in the same ballpark):

| Metric | Value |
| --- | --- |
| Runtime dependencies | **0** (standard library only) |
| Source | ~137 KB of Python across 21 small modules |
| Peak memory for one `ephor watch` | **~24 MB** RSS (≈22 MB is the Python interpreter itself) |
| Time for one scan | **~1.4 s** (reading `/proc` + the socket table) |
| Resident services | **none** — nothing runs between scans |
| On-disk state | one SQLite file + small cached feed text files |

In other words Ephor adds about **2 MB over bare Python** and runs for a second or two per sample. That's why
a Pi Zero 2 W (512 MB) handles it comfortably on a one-minute timer.

## How it compares

| | Ephor | Inline egress proxy (pipelock, agent-egress-proxy) | Heavy endpoint monitor (e.g. Aegis) |
| --- | --- | --- | --- |
| Setup | none — reads `/proc` | configure every agent to use the proxy | install an agent/service |
| Sees non-cooperating traffic | **yes** (socket table) | no — only what's routed through it | yes |
| Bypassable by a compromised agent | **no** | yes (route around the proxy) | varies |
| Blocks traffic | no (detect-only) | yes (that's the point) | sometimes |
| Dependencies | **none** | proxy runtime + config | heavier stack |
| Shows per-agent permissions | **yes** | no | partial |
| Platform focus | Linux / homelab | cross-platform | often Windows/desktop-first |

Ephor is **complementary** to an inline proxy, not a replacement: if you want to *block* egress, use a proxy;
if you want to *see everything, including what the proxy can't*, and understand blast radius, add Ephor.

## Install

```bash
pip install ephor         # once published
# or from source:
pip install .
```

Requires Python 3.11+ and `ss` (from `iproute2`, present on essentially every Linux). Run as root to attribute
connections owned by other users; as a normal user it only sees your own.

## Usage

```bash
ephor watch                 # sample now, record where each agent went + how much it pulled
ephor watch --resolve       # also reverse-DNS destinations (best-effort)
ephor watch --loop          # real-time: re-sample on an interval, alerting on new/dangerous activity
ephor watch --loop --interval 15                  # ...every 15 s
ephor watch --loop --webhook https://discord.com/api/webhooks/...   # push alerts to a webhook
ephor agents                # every agent seen, with download totals and bad-destination counts
ephor agent ollama          # one agent's destinations
ephor agent scraper --perms # ...plus its blast radius (user, caps, sudo, readable secrets)
ephor history --bad         # every known-bad destination ever recorded
ephor status                # database + feed summary
ephor feeds --refresh       # update the threat-feed cache now
ephor serve                 # read-only HTML view on 127.0.0.1:8799 (stdlib only)
ephor installs              # install commands agents ran, packages that appeared (v0.3)
ephor dns --flagged         # names agents looked up that a check flagged (v0.3)
ephor query "SELECT ..."    # read-only SQL over everything recorded (v0.3)
ephor probe --check         # can the optional eBPF probe run here? (v0.3)
```

Add `--json` to any read command for scripting. `ephor watch` **exits non-zero (2)** if it saw a connection to
a known-bad destination, so it drops straight into cron or a CI step:

```cron
* * * * * ephor watch >/dev/null || curl -fsS https://your-alert-hook/bad-agent-egress
```

Because Ephor samples point-in-time state, run `watch` on a short interval (every minute is plenty on a
homelab) for near-complete coverage. A connection that opens and closes entirely between two samples can be
missed — that's the honest trade-off for needing no proxy and no kernel hooks. The optional eBPF probe in v0.3 (`watch --loop --ebpf`) closes most of that gap.

## Threat feeds

Known-bad judgement comes from free, well-regarded public feeds, fetched at most once every
`feed_ttl_hours` and cached so matching works offline:

- **URLhaus** (abuse.ch) — malware-distribution hosts
- **Feodo Tracker** (abuse.ch) — botnet C2 IPs
- **FireHOL level1** — aggregated attack/abuse IP ranges
- **ThreatFox** (abuse.ch) — broader IOC IPs (off by default; noisier)

If the network is down, Ephor matches against the last good cache rather than failing.

## Real-time anomaly watch (`ephor watch --loop`)

`ephor watch` is one-shot by design; add `--loop` to turn it into a short, opt-in watch that re-samples on an
interval (`--interval N`, default 30 s) and fires an alert the moment an agent does something new or dangerous:

- a **large transfer to a host it has never used** — a destination outside its baseline pulling more than
  `large_transfer_bytes`,
- a **connection to a known-bad destination** — the same free threat-feed match as one-shot `watch`,
- an **unusual port** — a port that agent hasn't used before.

On startup the watch learns a per-agent baseline of "normal" destinations during a short **warm-up window**
(`warmup_seconds`, default 60 s), persisted in the same SQLite history. Only known-bad matches alert during
warm-up; the baseline anomalies are gated behind that window and the transfer threshold, so a quiet box stays
quiet.

Alerts go to a configurable sink: **stdout** (always), plus optionally a **webhook** (`--webhook URL` — Discord,
Slack, or any generic JSON endpoint via stdlib `urllib`) and/or **syslog** (`--syslog`). Each alert carries the
**originating host** (which box/CT), the **client binary** read from `/proc` (`curl`, headless
`chromium`/Playwright/Puppeteer, python `requests`, `node`, …), and a **destination category**.

Crawling is a first-class signal. Crawl/scrape clients (`chromium`/Playwright/Puppeteer, `crawl4ai`, `scrapy`,
`crawlee`) are classified as their own `crawler:*` type, and known **crawl/scrape SaaS endpoints** (e.g.
Firecrawl, Apify, ScrapingBee) are labelled as a `crawl-saas` destination category. Be honest about reach: a
self-hosted crawler exposes every target site to Ephor, while a hosted crawl API only shows the call to it and
the bytes returned — the pages it fetched happen off-box and are invisible to any passive host-side monitor.

The on-the-wire HTTP User-Agent is deliberately out of scope: it lives inside TLS, and reading it would need a
proxy, breaking Ephor's passive premise.

Sinks and thresholds are configurable in `ephor.toml`:

```toml
[alert]
webhook = "https://discord.com/api/webhooks/..."   # or Slack, or any JSON endpoint
syslog = false
warmup_seconds = 60
large_transfer_bytes = 1048576
```

## Supply chain: what agents run, install and look up (v0.3)

A coding agent's riskiest moment is rarely a connection it makes itself. It's the `pip install` it runs, the
`curl … | sh` it pastes, or the package name it half-remembers that someone has since registered. v0.3 watches
those. Everything here is still detect-only: nothing is blocked, nothing is executed on Ephor's behalf.

**Who started it.** Every process is followed up its parent chain to an agent Ephor recognises, so a `pip`
talking to PyPI is reported as `opencode via pip`, not as a stray `other:pip`. This works in the default
mode too: no eBPF needed.

**What got installed.** With `watch --loop`, Ephor snapshots what is installed every 5 minutes
(`--inventory-every`): Python site-packages (system, `/usr/local`, every user's `~/.local`, pipx venvs),
global npm, Homebrew, dpkg and apk. A new package is reported with the agents that were active when it
appeared. The first snapshot only learns. A snapshot of ~900 packages takes about 10 ms: it reads directory
names and two small database files.

**Is it dodgy?** New Python and npm packages, and the names in any install command, are looked up on
[OSV.dev](https://osv.dev) (`malicious_package`: OpenSSF's malicious-packages list) and on PyPI/npm
(`young_package`: first published under 30 days ago, the shape of "slopsquatting", where an attacker
registers a name AI models tend to invent). Only the package name and version leave the box. `--no-pkg-checks`
turns it off. With `--sieve`, and [sieve](https://github.com/casareanderson/sieve) installed, Ephor runs
`sieve path` where new packages landed and reports new known-exploited or malicious findings.

**What it looked up.** Each DNS name an agent resolves is checked offline:

| reason | what it means |
| --- | --- |
| `dns_feed` | the name is on URLhaus or ThreatFox |
| `dns_lookalike` | it borrows a registry's or code host's name without being it: `pypi-org.com`, `files-pythonhosted.net`, `npmjs-registry.com`, `githubusercontent.io`, `pypj.org` |
| `dns_punycode` | an internationalised (`xn--`) label, the classic way to look like another name |
| `dns_random` | a long, random-looking label, the shape malware-generated domains have |
| `dns_young` | registered in the last 30 days (opt-in `--rdap`, asks RDAP) |
| `doh` | a named agent connected to a DNS-over-HTTPS resolver, so its lookups skip the system resolver |

They are heuristics. A name you use on purpose goes in `dns_allow = ["example.com"]` in the config.

**Install alerts.** `install` when a named agent runs a package install, `pipe_to_shell` whenever a shell runs
`curl|wget … | sh` (whoever ran it), `new_package`, `malicious_package`, `young_package`, `sieve`.

### The eBPF probe (`watch --loop --ebpf`)

Sampling `ss` and `/proc` can't see a `pip install` that finishes between two samples, or a DNS lookup at all.
eBPF can, but loading eBPF programs needs a compiler, which the standard library doesn't have. So Ephor runs a
separate probe and reads its output, and Ephor itself stays dependency-free. Two backends print the same events:

- **[ephor-probe](probe/)**, the native probe: one ~2 MB static binary (x86_64 and arm64, attached to each
  release with a checksum, or `./probe/build.sh`). About **10 MB** of memory. Used whenever it is on PATH.
- **[bpftrace](https://github.com/bpftrace/bpftrace)**, the fallback: Ephor writes a small bpftrace program
  (`ephor probe --print`). One distro package, but about 110 MB of memory, because bpftrace carries a compiler.

Either backend reports three things, read-only:

- every process start, with its parent, cgroup and full command line, read from the new process's memory, so
  even a sub-second command is caught
- every DNS lookup made through libc `getaddrinfo`, with the process that asked. It hooks the host's libc and
  the libc inside each running container
- every outgoing TCP connection (SYN sent), so short-lived connections are seen too

```bash
ephor probe --check        # can it run here? (root, bpftrace, BTF)
ephor probe                # stream the raw events, attributed to agents
ephor watch --loop --ebpf  # the full watch with the probe on
```

It needs root, ephor-probe or bpftrace 0.16+, and a kernel with BTF (standard since about 5.8). An unprivileged container
can't load eBPF: run Ephor on the host, which sees every container's processes and labels them by container.
On the reference box (Proxmox host, agents in an LXC) a live test caught an agent's `pip install
requests==2.19.0`, a `curl | sh` and a lookup of `pypi-org.com`, each tied to the agent and its container.

**The cost, measured on the reference box:** ephor ~29 MB RSS and ~1.5% CPU, plus the probe: **ephor-probe ~10 MB
and ~1.4% CPU**, or bpftrace ~110 MB and ~1% CPU. With ephor-probe the eBPF view fits small boards too, as long as
the kernel has BTF. Without BTF, leave `--ebpf` off: inventory snapshots still catch every install, just not
the exact command.

### No eBPF? `ephor dns-proxy`

An opt-in, stdlib UDP DNS forwarder. Point the resolver at it (`--listen 127.0.0.1:5353`, upstream defaults to
your current nameserver). It passes every query on unchanged, ties each name to the asking process through its
source port (`/proc/net/udp`), and runs the same checks. It's the only part of Ephor that sits in a traffic
path, which is why it is separate and off by default. UDP only.

### Ask it anything: `ephor query`

Everything Ephor records is in one SQLite file, and `ephor query` runs read-only SQL over it, osquery-style:

```bash
ephor query --schema
ephor query "SELECT agent, via, name FROM dns WHERE flags != '' ORDER BY last_seen DESC"
ephor query "SELECT datetime(ts,'unixepoch'), agent, manager, packages FROM installs ORDER BY ts DESC LIMIT 20"
ephor query "SELECT root, manager, name, version, agents FROM packages WHERE baseline = 0"
```

The file is opened read-only and an authorizer refuses anything but reading, so a query can't change history.
`ephor installs` and `ephor dns` are the same data as ready-made lists.

## Power-user: VirusTotal (optional, off by default)

The free feeds above are downloaded *to* you and matched locally — **nothing about your machine leaves it.**
VirusTotal is the exception, and the only time Ephor talks to a third party, so it is **off by default**.

When you turn it on, Ephor can:

- check a destination's **domain/IP reputation** on VirusTotal, and
- where it can obtain a **hash of a downloaded file**, ask VirusTotal *"is this known malware?"*

> ⚠️ **Privacy.** Enabling VirusTotal means Ephor **sends destinations (and file hashes) to VirusTotal /
> Google**, a third party. That is the whole reason it's off by default and the reason Ephor prints a warning
> the first time you use it in a run. If Ephor's nothing-leaves-your-box promise is why you're here, leave
> this off.

Turn it on with a key (get a free one from virustotal.com) via config:

```toml
[virustotal]
enabled = true
api_key = "YOUR_VT_API_KEY"   # or set the VT_API_KEY env var
```

…or per-run: `ephor watch --virustotal`.

VirusTotal **enriches** the free-feed verdict — it never replaces it. The free feeds keep working with no key
and offline. To respect the free tier (4 requests/minute, 500/day) Ephor:

- only queries destinations the free feeds **didn't** already flag (no point spending quota on a known-bad),
- caches every verdict for a week so the same destination isn't re-queried,
- throttles to a few lookups per run and skips (rather than stalls) when it's calling too fast,
- and **fails soft** — if the key is missing, the quota is spent, or VT is unreachable, you simply get the
  free-feed verdict and Ephor never crashes.

Enabling VirusTotal adds **no dependency** — it uses the same standard-library HTTP client as the free feeds.

## Configuration

Everything works with no config. To add your own agent labels, tune the ignore list, pick feeds, point the
permissions view at your real secret files, or set up the anomaly watch's alert sink and thresholds, copy
[`ephor.toml.example`](ephor.toml.example) to `ephor.toml`, `~/.config/ephor/ephor.toml`, or
`/etc/ephor/ephor.toml`.

## How it works

1. `ss -tnpiH state established` lists every established outbound socket, the owning PID, and per-socket bytes.
2. For each PID, Ephor reads `/proc/<pid>/{cmdline,exe,status,cgroup}` to identify the process, its user, its
   capabilities, and its container (best-effort).
3. A configurable classifier turns the process into a stable **agent** label (`hermes:coder`, `ollama`,
   `langchain`, `py:myscript`, …). Noise — sshd, systemd, cron, and Claude Code itself — is ignored.
4. Each public-internet destination is matched against the cached threat feeds and folded into a small SQLite
   history (first/last seen, times seen, bytes received, bad flag).
5. `--perms` adds the live blast-radius snapshot for an agent that's currently running.

## Limits (read these)

- **Point-in-time sampling.** Very short-lived connections between samples can be missed. Run on a timer.
- **IP-first.** Passive inspection gives an IP, not the hostname/SNI the agent asked for; `--resolve` adds
  best-effort reverse DNS, which is imperfect. IP and CIDR feeds match regardless.
- **Attribution needs privilege.** As non-root you only see your own processes' connections.
- **Detect-only.** Ephor never blocks. If you need enforcement, pair it with a proxy or firewall.
- **Linux only.** It depends on `/proc` and `ss`.

## Roadmap

- An ESP/embedded **hardware alert sink** (a buzzer or LED that Ephor pings over the LAN), the add-on output
  noted under *Runs on tiny hardware* above.

## The warden family

Three tools, one job: knowing what's actually happening on your homelab. Each one runs on its own, and warden is
the big brother that brings it all into one place.

| Tool | Watches | Runs as |
|---|---|---|
| **[warden](https://github.com/casareanderson/warden)** | The whole estate: intrusions, bans, vulnerabilities, patches and AI agents, in one console you review and approve from | A server + web console |
| **[sieve](https://github.com/casareanderson/sieve)** | Known vulnerabilities in packages, container images and lockfiles (OSV.dev + CISA KEV + EPSS) | A CLI or GitHub Action: `pipx install sieve-scan` |
| **[ephor](https://github.com/casareanderson/ephor)** | What the AI agents on a Linux box connect to, download and can access | A dependency-free CLI that runs down to a Pi Zero |

sieve and ephor both started life inside warden and were pulled out so you can use just the piece you need.

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q
ruff check .
```

The test suite is fully offline — it feeds fixture `ss` output and fixture feed caches, so no network or root
is needed.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
