"""Supply-chain watch: what agents run, look up and install. Used by `watch --loop`.

Two sources feed it:

  * the eBPF probe (`--ebpf`): every process start, DNS lookup and outgoing connection as it happens
  * inventory snapshots (every `--inventory-every` seconds, on by default): what is installed on the host and
    inside each container a named agent has acted in

and it turns them into alerts:

  install            a named agent ran a package install (pip, npm, brew, apt, cargo, go, gem...)
  pipe_to_shell      something ran `curl ... | sh` (always alerts and keeps a copy; block_pipe_to_shell also kills it)
  new_package        a package appeared since the last snapshot (with the agents active at the time)
  malicious_package  OSV.dev lists the package as malicious (MAL-*)
  young_package      the package was first published days ago
  sieve              sieve found known-exploited or malicious packages where the new ones landed (`--sieve`)
  dns_feed / dns_lookalike / dns_punycode / dns_random / dns_young   a name an agent looked up (see dnscheck)
  doh                a named agent connected to a DNS-over-HTTPS resolver, bypassing the system resolver
"""
from __future__ import annotations

import glob
import os
import signal
import sys
import time

from . import collect, config, dnscheck, installs, lineage, pkgcheck, probe, store

INSTALL = "install"
PIPE_TO_SHELL = "pipe_to_shell"
NEW_PACKAGE = "new_package"
MALICIOUS_PACKAGE = "malicious_package"
YOUNG_PACKAGE = "young_package"
SIEVE = "sieve"
DOH = "doh"
IMMEDIATE = {PIPE_TO_SHELL, MALICIOUS_PACKAGE, "dns_feed", "dns_lookalike", SIEVE}
PER_SNAPSHOT_DETAIL = 20          # more new packages than this in one snapshot -> one summary alert
CHECKS_PER_SNAPSHOT = 60          # network lookups per snapshot, so an `apt upgrade` doesn't hammer OSV


class Supply:
    def __init__(self, *, ebpf: bool, inventory_every: int, pkg_checks: bool, use_sieve: bool, rdap: bool,
                 matcher, roots: list[str] | None = None, proc: str = "/proc",
                 block_pipe_to_shell: bool | None = None, quarantine_dir: str = "") -> None:
        self.proc = proc
        self.resolver = lineage.Resolver(proc)
        self.stream = probe.Stream() if ebpf else None
        self.next_libc_check = time.time() + 600
        self.inventory_every = max(0, int(inventory_every))
        self.next_inventory = 0.0
        self.pkg_checks = pkg_checks
        self.use_sieve = use_sieve
        self.rdap = rdap
        self.matcher = matcher
        self.block_pipe_to_shell = config.block_pipe_to_shell() if block_pipe_to_shell is None else block_pipe_to_shell
        self.quarantine_dir = quarantine_dir or config.quarantine_dir()
        self.roots: dict[str, str] = {r if r != "/" else "host": r for r in (roots or ["/"])}
        self.container_pid: dict[str, int] = {}
        self.me = os.getpid()
        self.recent: dict[tuple, float] = {}          # (agent, manager, packages) -> when, to fold repeats

    # ------------------------------------------------------------ helpers

    def _container(self, pid: int, cgroup: str = "") -> str:
        if cgroup:
            return collect.container_of(pid, cgroup)
        cg = ""
        try:
            with open(f"{self.proc}/{pid}/cgroup") as f:
                lines = f.read().strip().splitlines()
            cg = lines[-1] if lines else ""
        except OSError:
            pass
        return collect.container_of(pid, cg)

    def _track_root(self, container: str, pid: int) -> None:
        if container and container not in self.roots:
            self.container_pid[container] = pid
            self.roots[container] = ""             # resolved to /proc/<pid>/root at snapshot time

    def _root_path(self, label: str) -> str:
        path = self.roots.get(label, "")
        if path and (path == "/" or os.path.isdir(path)):
            return path
        pid = self.container_pid.get(label, 0)
        if pid and os.path.isdir(f"{self.proc}/{pid}/root"):
            return f"{self.proc}/{pid}/root"
        for d in glob.glob(f"{self.proc}/[0-9]*"):              # the pid exited: find another one in there
            p = int(os.path.basename(d))
            if self._container(p) == label:
                self.container_pid[label] = p
                return f"{d}/root"
        return ""

    # ------------------------------------------------------------ probe events

    def _children(self, pid: int) -> list[int]:
        out = []
        for f in glob.glob(f"{self.proc}/{pid}/task/*/children"):
            try:
                out += [int(c) for c in open(f).read().split()]
            except (OSError, ValueError):
                pass
        return out

    def _block(self, pid: int) -> None:
        """Kill the shell running the pipe and everything under it (curl, the inner sh).
        Never the process group: in a script or a service that is the parent too.
        The payload may already have started by the time the exec event arrives."""
        if pid <= 1 or pid == self.me:
            return
        todo, seen = [pid], []
        while todo and len(seen) < 64:
            p = todo.pop()
            if p > 1 and p != self.me and p not in seen:
                seen.append(p)
                todo += self._children(p)
        for p in reversed(seen):           # children first
            try:
                os.kill(p, signal.SIGKILL)
            except OSError:
                pass

    def _quarantine(self, payload: str, cmd: str, pid: int, agent: str, container: str, now: int) -> None:
        """Keep the URL + command for inspection (0600: a command line can carry a token)."""
        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)
            path = os.path.join(self.quarantine_dir, f"{now}-{pid}.txt")
            with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as f:
                f.write(f"# pipe_to_shell payload quarantined by ephor at {now}\n"
                        f"agent: {agent}\ncontainer: {container or '-'}\nurl: {payload}\ncmd: {cmd}\n")
        except OSError:
            pass

    def handle_events(self, db, now: int, emit, on_conn) -> None:
        if not self.stream:
            return
        if not self.stream.alive():
            print(f"ephor: eBPF probe stopped: {self.stream.error() or 'no reason given'}; restarting",
                  file=sys.stderr)
            self.stream = probe.Stream()
            return
        if time.time() >= self.next_libc_check:
            self.next_libc_check = time.time() + 600
            if set(probe.libcs(self.proc)) != set(self._libcs_now()):
                self.stream.stop()                 # a container started or stopped: re-hook its libc
                self.stream = probe.Stream()
        for ev in self.stream.drain():
            if ev.pid == self.me or ev.ppid == self.me or self.resolver.descends_from(ev.pid, self.me):
                if ev.kind == "exec":
                    self.resolver.note(ev.pid, ev.ppid, ev.cmd)
                continue                           # Ephor's own lookups, and sieve when Ephor runs it
            if ev.kind == "exec":
                self._exec(db, now, ev, emit)
            elif ev.kind == "dns":
                self._dns(db, now, ev, emit)
            elif ev.kind == "connect" and collect.is_internet(ev.ip):
                agent, via = self.resolver.resolve(ev.pid)
                if agent.startswith("other:"):
                    continue                       # system tools: the ss sampler still sees their long connections
                container = self._container(ev.pid, ev.cgroup)
                on_conn(agent, via, container, ev.ip, ev.port, 0, ev.comm)
                if dnscheck.doh_endpoint(ev.ip, ev.port) and lineage.is_named(agent):
                    emit(DOH, agent=agent, via=via, container=container, dest=ev.ip, port=ev.port,
                         detail="DNS-over-HTTPS resolver: lookups bypass the system resolver")

    def _libcs_now(self) -> list[str]:
        return list(self.stream.libs) if self.stream else []

    def _exec(self, db, now: int, ev: probe.Event, emit) -> None:
        cmd = ev.cmd
        self.resolver.note(ev.pid, ev.ppid, cmd)
        agent, via = self.resolver.resolve(ev.pid, cmd)
        container = self._container(ev.pid, ev.cgroup)
        named = lineage.is_named(agent)
        if named and via:
            store.record_exec(db, agent, via, cmd, container, now)
            self._track_root(container, ev.pid)
        ic = installs.parse_command(cmd)
        if not ic:
            return
        key = (agent, ic.manager, tuple(ic.packages))
        if time.time() - self.recent.get(key, 0) < 30:
            return                                 # the same install seen again through a wrapper shell
        self.recent[key] = time.time()
        if len(self.recent) > 5000:
            self.recent.clear()
        flags = []
        if self.pkg_checks and pkgcheck.ecosystem(ic.manager):
            for spec in ic.packages[:10]:
                name = installs.bare_name(spec)
                ver = spec.split("==", 1)[1] if "==" in spec else ""
                for reason, detail in pkgcheck.check(ic.manager, name, ver):
                    flags.append(reason)
                    emit(reason, agent=agent, via=via, container=container, dest=f"{ic.manager}:{name}",
                         detail=detail)
        store.record_install(db, now, agent, via, ic.manager, ic.packages, cmd, container, ",".join(flags))
        if ic.manager == "pipe-to-shell":
            self._quarantine(ic.packages[0], cmd, ev.pid, agent, container, now)
            if self.block_pipe_to_shell:
                self._block(ev.pid)
            emit(PIPE_TO_SHELL, agent=agent, via=via, container=container, dest=ic.packages[0],
                 detail=cmd[:160] + (" (blocked)" if self.block_pipe_to_shell else ""))
        elif named:
            emit(INSTALL, agent=agent, via=via, container=container,
                 dest=f"{ic.manager}:{' '.join(ic.packages[:5])}", detail=cmd[:160])

    def _dns(self, db, now: int, ev: probe.Event, emit) -> None:
        if not ev.name:
            return
        agent, via = self.resolver.resolve(ev.pid)
        container = self._container(ev.pid, ev.cgroup)
        self.note_dns(db, now, agent, via, container, ev.name, emit)

    def note_dns(self, db, now: int, agent: str, via: str, container: str, name: str, emit) -> None:
        """Record one looked-up name and alert on what the checks find (shared with dns-proxy)."""
        found = dnscheck.check(name, self.matcher)
        if self.rdap and not found:
            age = dnscheck.young_domain(name)
            if age is not None:
                found.append(("dns_young", f"registered {age} day(s) ago"))
        store.record_dns(db, agent, via, name, container, now, ",".join(r for r, _ in found))
        for reason, detail in found:
            emit(reason, agent=agent, via=via, container=container, dest=name, detail=detail)

    # ------------------------------------------------------------ inventory

    def inventory_due(self) -> bool:
        return self.inventory_every > 0 and time.time() >= self.next_inventory

    def inventory(self, db, now: int, emit) -> None:
        self.next_inventory = time.time() + self.inventory_every
        for label in list(self.roots):
            path = self._root_path(label)
            if not path:
                continue
            snap = installs.snapshot(path)
            if not snap:
                continue
            if not store.has_inventory(db, label):
                store.add_packages(db, label, snap, now, baseline=True)       # first look: learn, don't alert
                continue
            added, removed = installs.diff(store.known_packages(db, label), snap)
            if removed:
                store.gone_packages(db, label, removed, now)
            if not added:
                continue
            active = store.recent_agents(db, now - self.inventory_every - 120)
            who = ",".join(active)
            store.add_packages(db, label, added, now, agents=who)
            container = "" if label == "host" else label
            if len(added) > PER_SNAPSHOT_DETAIL:
                names = ", ".join(f"{n} {v}" for _, n, v, _ in added[:8])
                emit(NEW_PACKAGE, agent=who or "unknown", container=container, dest=f"{len(added)} packages",
                     detail=f"{names}, …")
            else:
                for m, n, v, loc in added:
                    emit(NEW_PACKAGE, agent=who or "unknown", container=container, dest=f"{m}:{n} {v}",
                         detail=loc)
            checks = 0
            for pkg in added:
                m, n, v, loc = pkg
                if not self.pkg_checks or not pkgcheck.ecosystem(m) or checks >= CHECKS_PER_SNAPSHOT:
                    continue
                checks += 1
                found = pkgcheck.check(m, n, v)
                if found:
                    store.flag_package(db, label, pkg, ",".join(r for r, _ in found))
                for reason, detail in found:
                    emit(reason, agent=who or "unknown", container=container, dest=f"{m}:{n} {v}", detail=detail)
            if self.use_sieve:
                for loc in sorted({loc for m, _, _, loc in added if m in ("pypi", "npm")}):
                    res = pkgcheck.sieve_path(path.rstrip("/") + loc)
                    if res and (res[0] or res[1]):
                        emit(SIEVE, agent=who or "unknown", container=container, dest=loc,
                             detail=f"sieve: {res[0]} known-exploited, {res[1]} malicious")

    def stop(self) -> None:
        if self.stream:
            self.stream.stop()
