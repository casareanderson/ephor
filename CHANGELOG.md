# Changelog

## 0.3.0 (2026-10-12)

Supply chain: what agents run, install and look up.

- **Who started it:** every process is followed up its parent chain to a named agent (`opencode via pip`).
- **Inventory snapshots** in `watch --loop` (`--inventory-every`, default 300 s): Python, npm, Homebrew, dpkg,
  apk. New packages alert with the agents active at the time.
- **Install commands:** pip/uv/pipx, npm/npx/pnpm/yarn/bun, brew, apt/dnf/apk, cargo, go, gem, and `curl | sh`.
- **Package checks:** OSV.dev malicious (MAL-*) and first-published age on PyPI/npm; `--no-pkg-checks` to turn
  off; `--sieve` runs sieve where new packages land.
- **DNS checks:** feeds, lookalikes of registries and code hosts, punycode, random-looking names, DoH bypass,
  optional registration age (`--rdap`); `dns_allow` in the config.
- **eBPF probe** (`watch --loop --ebpf`, `ephor probe`): process starts with full command lines, libc DNS
  lookups (host and every container) and TCP connects. Backends: the native **ephor-probe** (probe/, ~2 MB static
  binary, ~10 MB RSS, x86_64 + arm64 built by CI and attached to releases) or bpftrace as a fallback. Optional;
  needs root and BTF.
- **`ephor dns-proxy`:** opt-in UDP DNS forwarder that ties names to processes on boxes without eBPF.
- **`ephor query`:** read-only SQL over the history; `ephor installs`, `ephor dns`.
- Ephor's own connections (feed and OSV lookups) are no longer reported.

## 0.2.0

- `ephor watch --loop`: real-time anomaly watch with webhook and syslog alerts.
