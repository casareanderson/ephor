"""Command line. Detect-only: Ephor reports, it never blocks, kills or firewalls anything.

  ephor watch [--resolve] [--no-feeds]   take one sample, attribute it, fold it into history
  ephor watch --loop [--interval N]      re-sample on an interval, alerting on new/dangerous activity
  ephor agents                           every agent seen, with destination count and bytes pulled
  ephor agent <name> [--perms]           one agent's destinations (and, with --perms, its blast radius)
  ephor history [--agent A] [--bad]      the destination log, newest first
  ephor status                           database + feed summary
  ephor feeds [--refresh]                threat-feed cache state
  ephor serve [--host] [--port]          read-only HTML view (stdlib only; LAN use)

Add --json to any read command for machine-readable output. `watch` exits non-zero if a connection to a
known-bad destination was seen in that sample, so it drops straight into cron or a CI step.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import __version__, collect, config, feeds, perms, resolve, store, virustotal

EXIT_OK = 0
EXIT_BAD = 2  # a known-bad destination was observed


def _age(ts: int) -> str:
    if not ts:
        return "never"
    d = int(time.time()) - ts
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if d >= n:
            return f"{d // n}{unit} ago"
    return f"{d}s ago"


def _fmt_bytes(n: int) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def cmd_watch(args) -> int:
    if args.loop:
        from . import watch
        return watch.run_loop(args)
    s = collect.sample()
    if not s.have_ss:
        print("ephor: 'ss' (iproute2) not found — cannot read the socket table", file=sys.stderr)
        return 1
    if not s.is_root:
        print("ephor: not running as root — only connections owned by this user are attributable",
              file=sys.stderr)
    conns = collect.attribute(s)
    matcher = None if args.no_feeds else feeds.Matcher()
    vt = None
    if virustotal.enabled(getattr(args, "virustotal", False)):
        vt = virustotal.VirusTotal()
        print(virustotal.PRIVACY_WARNING, file=sys.stderr)
    vt_budget = 3  # at most a few VT lookups per run, so a busy box never blows the free-tier quota
    db = store.connect()
    bad_seen = False
    agents_seen = set()
    with db:
        for c in conns:
            agents_seen.add(c.agent)
            dest = resolve.ptr(c.rip) if args.resolve else c.rip
            is_bad, indicator, feed = (False, "", "")
            if matcher:
                is_bad, indicator, feed = matcher.check(ip=c.rip, domain=dest if args.resolve else "")
            # VirusTotal only enriches destinations the free feeds didn't already flag, and only a few per run.
            if vt and not is_bad and vt_budget > 0:
                vt_budget -= 1
                res = vt.check_destination(ip=c.rip, domain=dest if args.resolve else "")
                if res and (res["malicious"] > 0 or res["suspicious"] > 1):
                    is_bad, indicator, feed = True, dest, "virustotal"
            store.record_conn(db, c.agent, dest, c.rip, c.rport, s.ts, c.bytes_recv, is_bad, feed)
            if is_bad:
                bad_seen = True
                store.record_alert(db, c.agent, dest, c.rip, feed, indicator, s.ts)
        for a in agents_seen:
            store.record_agent(db, a, s.ts)
    if args.json:
        print(json.dumps({
            "ts": s.ts, "host": s.host, "root": s.is_root,
            "connections": len(conns), "agents": sorted(agents_seen), "bad_seen": bad_seen,
        }))
    else:
        print(f"ephor: {len(conns)} agent connection(s), {len(agents_seen)} agent(s)"
              + (" — \033[31mKNOWN-BAD destination seen\033[0m" if bad_seen else ""))
    db.close()
    return EXIT_BAD if bad_seen else EXIT_OK


def cmd_agents(args) -> int:
    db = store.connect()
    rows = store.agents(db)
    db.close()
    if args.json:
        print(json.dumps(rows, indent=2))
        return EXIT_OK
    if not rows:
        print("no agents recorded yet — run 'ephor watch' (ideally on a timer)")
        return EXIT_OK
    print(f"{'AGENT':<24} {'DESTS':>5} {'DOWNLOADED':>10} {'BAD':>3}  {'LAST SEEN':<10}")
    for r in rows:
        flag = f"\033[31m{r['bad_dests']}\033[0m" if r["bad_dests"] else "0"
        print(f"{r['agent']:<24} {r['dests']:>5} {_fmt_bytes(r['bytes_recv']):>10} {flag:>3}  "
              f"{_age(r['last_seen']):<10}")
    return EXIT_OK


def cmd_agent(args) -> int:
    db = store.connect()
    rows = store.agent_conns(db, args.name)
    if args.perms:
        s = collect.sample()
        snap = None
        for c in collect.attribute(s):
            if c.agent == args.name:
                snap = perms.snapshot(c.pid, c.user, config.secret_paths())
                break
    db.close()
    if args.json:
        out = {"agent": args.name, "destinations": rows}
        if args.perms:
            out["permissions"] = snap
        print(json.dumps(out, indent=2))
        return EXIT_OK
    if not rows:
        print(f"no destinations recorded for agent '{args.name}'")
    else:
        print(f"== {args.name}: {len(rows)} destination(s) ==")
        print(f"{'DESTINATION':<40} {'PORT':>5} {'DOWNLOADED':>10} {'SEEN':>5}  FLAG")
        for r in rows:
            flag = f"\033[31mBAD:{r['feed']}\033[0m" if r["bad"] else ""
            print(f"{r['dest']:<40} {r['port']:>5} {_fmt_bytes(r['bytes_recv']):>10} {r['times_seen']:>5}  {flag}")
    if args.perms:
        if not snap:
            print("\npermissions: agent not currently running (snapshot needs a live process)")
        else:
            idn = snap["identity"]
            print(f"\n== {args.name}: permissions (blast radius) ==")
            print(f"  runs as     : {idn['user']} (uid {idn['uid']})  groups: {', '.join(idn['groups']) or '-'}")
            print(f"  sudo nopass : {snap['sudo']}")
            caps = snap["caps"] or ["(none)"]
            hi = set(snap["high_risk_caps"])
            print("  capabilities: " + ", ".join(
                (f"\033[31m{c}\033[0m" if c in hi else c) for c in caps))
            secs = snap["readable_secrets"]
            print(f"  can read    : {', '.join(secs) if secs else '(no configured secret paths readable)'}")
    return EXIT_OK


def cmd_history(args) -> int:
    db = store.connect()
    rows = store.history(db, agent=args.agent, bad_only=args.bad)
    db.close()
    if args.json:
        print(json.dumps(rows, indent=2))
        return EXIT_OK
    if not rows:
        print("no history")
        return EXIT_OK
    print(f"{'AGENT':<20} {'DESTINATION':<34} {'PORT':>5} {'DOWNLOADED':>10} {'LAST':<9} FLAG")
    for r in rows:
        flag = f"\033[31mBAD:{r['feed']}\033[0m" if r["bad"] else ""
        print(f"{r['agent']:<20} {r['dest']:<34} {r['port']:>5} {_fmt_bytes(r['bytes_recv']):>10} "
              f"{_age(r['last_seen']):<9} {flag}")
    return EXIT_OK


def cmd_status(args) -> int:
    db = store.connect()
    st = store.stats(db)
    db.close()
    m = feeds.Matcher()
    st["feed_indicators"] = m.total()
    st["version"] = __version__
    if args.json:
        print(json.dumps(st, indent=2))
        return EXIT_OK
    print(f"ephor {__version__}")
    print(f"  agents tracked     : {st['agents']}")
    print(f"  destinations        : {st['destinations']}  ({st['bad_destinations']} known-bad)")
    print(f"  alerts              : {st['alerts']}")
    print(f"  feed indicators     : {st['feed_indicators']}")
    vt_on = virustotal.enabled()
    budget = virustotal.VirusTotal().budget if vt_on else None
    print(f"  virustotal          : {'on' if vt_on else 'off'}"
          + (f" ({budget['left']}/{budget['cap']} left today)" if budget else ""))
    print(f"  last sample         : {_age(st['last_sample'])}")
    print(f"  database            : {config.db_path()}")
    return EXIT_OK


def cmd_feeds(args) -> int:
    if args.refresh:
        status = feeds.refresh(force=True)
    else:
        status = feeds.refresh(force=False)
    m = feeds.Matcher()
    if args.json:
        print(json.dumps({"feeds": status, "indicators_loaded": m.total()}, indent=2))
        return EXIT_OK
    for name, (state, count) in status.items():
        print(f"  {name:<12} {state:<12} {count} line(s)")
    print(f"  loaded indicators: {m.total()}")
    return EXIT_OK


def cmd_query(args) -> int:
    import sqlite3

    from . import query
    if args.schema:
        print(query.schema())
        return EXIT_OK
    if not args.sql:
        print("ephor: give a SELECT, or --schema to see the tables", file=sys.stderr)
        return 1
    try:
        cols, rows = query.run(args.sql, limit=args.limit)
    except sqlite3.Error as e:
        print(f"ephor: {e}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps([dict(zip(cols, r, strict=True)) for r in rows], indent=1, default=str))
    elif cols:
        print(query.table(cols, rows))
    return EXIT_OK


def cmd_installs(args) -> int:
    db = store.connect()
    cmds, pkgs = store.installs(db, args.limit), store.new_packages(db, args.limit)
    db.close()
    if args.json:
        print(json.dumps({"commands": cmds, "new_packages": pkgs}, indent=1))
        return EXIT_OK
    print(f"install commands ({len(cmds)}):")
    for r in cmds:
        flag = f"  \033[31m{r['flags']}\033[0m" if r["flags"] else ""
        via = f" via {r['via']}" if r["via"] else ""
        print(f"  {_age(r['ts']):<10} {r['agent']}{via:<14} {r['manager']:<8} {r['packages'][:60]}{flag}")
    print(f"\nnew packages since the first snapshot ({len(pkgs)}):")
    for r in pkgs:
        flag = f"  \033[31m{r['flags']}\033[0m" if r["flags"] else ""
        print(f"  {_age(r['first_seen']):<10} {r['root']:<10} {r['manager']}:{r['name']} {r['version']}"
              f"  [{r['agents'] or 'no agent seen'}]{flag}")
    return EXIT_OK


def cmd_dns(args) -> int:
    db = store.connect()
    rows = store.dns_names(db, agent=args.agent, flagged=args.flagged, limit=args.limit)
    db.close()
    if args.json:
        print(json.dumps(rows, indent=1))
        return EXIT_OK
    for r in rows:
        flag = f"  \033[31m{r['flags']}\033[0m" if r["flags"] else ""
        print(f"{_age(r['last_seen']):<10} {r['agent']:<20} {r['times_seen']:>5}  {r['name']}{flag}")
    return EXIT_OK


def cmd_probe(args) -> int:
    from . import probe
    if args.print:
        print(probe.program(probe.libcs()))
        return EXIT_OK
    why = probe.check()
    if args.check or why:
        if why:
            print("ephor: the eBPF probe can't run here:\n  - " + "\n  - ".join(why), file=sys.stderr)
            return 1
        libs = probe.libcs()
        light = "" if probe.native() else " (install ephor-probe for ~10 MB instead of ~110 MB)"
        print(f"ephor: eBPF probe ready: backend {probe.backend()}{light}, root, BTF; "
              f"DNS hooks on {len(libs)} libc file(s)")
        return EXIT_OK
    from . import lineage
    st = probe.Stream()
    res = lineage.Resolver()
    print("ephor: probe running; Ctrl-C to stop", file=sys.stderr)
    try:
        while st.alive():
            for ev in st.drain():
                if ev.kind == "exec":
                    res.note(ev.pid, ev.ppid, ev.cmd)
                agent, via = res.resolve(ev.pid, ev.cmd if ev.kind == "exec" else "")
                what = ev.cmd if ev.kind == "exec" else ev.name if ev.kind == "dns" else f"{ev.ip}:{ev.port}"
                print(f"{ev.kind:<7} {ev.pid:>7} {agent}{' via ' + via if via else ''}  {what[:160]}", flush=True)
            time.sleep(0.5)
        print(f"ephor: probe stopped: {st.error()}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return EXIT_OK
    finally:
        st.stop()


def cmd_dnsproxy(args) -> int:
    from . import dnsproxy, lineage, supply, watch
    matcher = None if args.no_feeds else feeds.Matcher()
    sp = supply.Supply(ebpf=False, inventory_every=0, pkg_checks=False, use_sieve=False, rdap=args.rdap,
                       matcher=matcher)
    res = lineage.Resolver()
    sinks = watch.make_sinks(args.webhook or "", args.syslog)
    upstream = args.upstream or dnsproxy.upstream_from_resolv()
    host = os.uname().nodename

    def on_query(pid: int, name: str) -> None:
        agent, via = res.resolve(pid) if pid else ("unknown", "")
        db = store.connect()
        now = int(time.time())

        def emit(reason, *, agent, via="", container="", dest="", detail="", **_):
            store.record_alert(db, agent, dest, "", reason, detail[:200], now)
            a = watch.Alert(ts=now, host=host, container=container, agent=agent, client="", crawler=False,
                            dest=dest, ip="", port=0, bytes_recv=0, reason=reason, via=via, detail=detail)
            for s in sinks:
                s.send(a)
        with db:
            sp.note_dns(db, now, agent, via, "", name, emit)
        db.close()
    print(f"ephor: dns-proxy on {args.listen} -> {upstream}; point the resolver at it. Ctrl-C to stop",
          file=sys.stderr)
    try:
        dnsproxy.serve(args.listen, upstream, on_query)
    except KeyboardInterrupt:
        return EXIT_OK
    except OSError as e:
        print(f"ephor: dns-proxy: {e}", file=sys.stderr)
        return 1
    return EXIT_OK


def cmd_serve(args) -> int:
    from . import serve as _serve
    return _serve.run(args.host, args.port)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ephor", description="Passive, detect-only monitor of AI-agent network activity.")
    p.add_argument("--version", action="version", version=f"ephor {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("watch", help="sample current connections and record them")
    w.add_argument("--resolve", action="store_true", help="reverse-DNS destinations (best-effort)")
    w.add_argument("--no-feeds", action="store_true", help="skip threat-feed matching this run")
    w.add_argument("--virustotal", action="store_true",
                   help="also enrich via VirusTotal (sends destinations to a third party; needs a key)")
    w.add_argument("--loop", action="store_true",
                   help="run continuously, re-sampling and alerting on new/dangerous activity")
    w.add_argument("--interval", type=int, default=30, metavar="N",
                   help="seconds between samples in --loop mode (default 30)")
    w.add_argument("--webhook", help="POST alerts to a Discord/Slack/generic JSON webhook URL")
    w.add_argument("--syslog", action="store_true", help="also emit alerts to syslog")
    w.add_argument("--json", action="store_true")
    w.add_argument("--ebpf", action="store_true",
                   help="with --loop: also read the eBPF probe (every command, DNS lookup and connection as it "
                        "happens; needs root and bpftrace, run on the host)")
    w.add_argument("--inventory-every", type=int, default=300, metavar="N",
                   help="with --loop: snapshot installed packages every N seconds and alert on new ones "
                        "(default 300, 0 = off)")
    w.add_argument("--inventory-root", action="append", metavar="PATH",
                   help="with --loop: snapshot packages under this root too (repeatable; default /, plus each "
                        "container a named agent acts in, when --ebpf is on)")
    w.add_argument("--no-pkg-checks", action="store_true",
                   help="don't look new packages up on OSV.dev (malicious) or PyPI/npm (first published)")
    w.add_argument("--sieve", action="store_true",
                   help="run `sieve path` where new Python/npm packages land (needs sieve installed)")
    w.add_argument("--rdap", action="store_true",
                   help="look up when each new domain an agent resolves was registered (network, RDAP)")
    w.set_defaults(func=cmd_watch)

    a = sub.add_parser("agents", help="list all agents seen")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_agents)

    g = sub.add_parser("agent", help="show one agent's destinations (and --perms)")
    g.add_argument("name")
    g.add_argument("--perms", action="store_true", help="also show what the agent can access, if live")
    g.add_argument("--json", action="store_true")
    g.set_defaults(func=cmd_agent)

    h = sub.add_parser("history", help="destination log")
    h.add_argument("--agent", help="filter to one agent")
    h.add_argument("--bad", action="store_true", help="only known-bad destinations")
    h.add_argument("--json", action="store_true")
    h.set_defaults(func=cmd_history)

    s = sub.add_parser("status", help="database and feed summary")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_status)

    f = sub.add_parser("feeds", help="threat-feed cache state")
    f.add_argument("--refresh", action="store_true", help="force a refetch now")
    f.add_argument("--json", action="store_true")
    f.set_defaults(func=cmd_feeds)

    q = sub.add_parser("query", help="read-only SQL over the history (osquery-style)")
    q.add_argument("sql", nargs="?", help='e.g. "SELECT agent, name FROM dns WHERE flags != \'\'"')
    q.add_argument("--schema", action="store_true", help="print the tables")
    q.add_argument("--limit", type=int, default=1000, metavar="N")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_query)

    i = sub.add_parser("installs", help="install commands agents ran, and packages that appeared")
    i.add_argument("--limit", type=int, default=50, metavar="N")
    i.add_argument("--json", action="store_true")
    i.set_defaults(func=cmd_installs)

    d = sub.add_parser("dns", help="names agents looked up (from --ebpf or dns-proxy)")
    d.add_argument("--agent", help="filter to one agent")
    d.add_argument("--flagged", action="store_true", help="only names a check flagged")
    d.add_argument("--limit", type=int, default=200, metavar="N")
    d.add_argument("--json", action="store_true")
    d.set_defaults(func=cmd_dns)

    pr = sub.add_parser("probe", help="the eBPF probe on its own: --check, --print, or stream events")
    pr.add_argument("--check", action="store_true", help="can the probe run here?")
    pr.add_argument("--print", action="store_true", help="print the bpftrace program it would run")
    pr.set_defaults(func=cmd_probe)

    dp = sub.add_parser("dns-proxy", help="opt-in local DNS forwarder that ties each name to the process "
                                          "(for boxes without eBPF)")
    dp.add_argument("--listen", default="127.0.0.1:5353", metavar="ADDR:PORT")
    dp.add_argument("--upstream", metavar="IP", help="real resolver (default: first nameserver in resolv.conf)")
    dp.add_argument("--no-feeds", action="store_true")
    dp.add_argument("--rdap", action="store_true", help="also check how recently each domain was registered")
    dp.add_argument("--webhook", help="POST alerts to a Discord/Slack/generic JSON webhook URL")
    dp.add_argument("--syslog", action="store_true")
    dp.set_defaults(func=cmd_dnsproxy)

    sv = sub.add_parser("serve", help="read-only HTML view (stdlib; bind to LAN only)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8799)
    sv.set_defaults(func=cmd_serve)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
