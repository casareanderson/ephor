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
