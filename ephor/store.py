"""History — a tiny SQLite file (stdlib `sqlite3`, no server, no ORM).

Each `watch` sample is folded into these tables:

  agents        one row per agent label: first/last seen, how many samples it appeared in
  conns         one row per (agent, dest, port): first/last seen, sample count, bytes received, bad flag
  alerts        one row per (agent, dest, feed) when a destination or name matched a feed or a check
  dns           one row per (agent, name): names an agent looked up (eBPF probe or dns-proxy)
  execs         one row per (agent, command): commands a named agent started (eBPF probe)
  installs      one row per install command seen (pip/npm/brew/apt/... or curl | sh), with the agent
  packages      what is installed where, from inventory snapshots: first seen, gone, and which agents were
                active when it appeared

`ephor query "SELECT ..."` runs read-only SQL over all of them.

The design is deliberately boring: upserts keyed on the natural identity of a thing, counters that only go up,
and a single file you can copy, inspect with the `sqlite3` CLI, or delete to reset. No migrations engine —
just `CREATE TABLE IF NOT EXISTS`.
"""
from __future__ import annotations

import sqlite3
import time
from contextlib import closing

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
  agent TEXT PRIMARY KEY,
  first_seen INTEGER, last_seen INTEGER, samples INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS conns (
  agent TEXT, dest TEXT, ip TEXT, port INTEGER,
  first_seen INTEGER, last_seen INTEGER, times_seen INTEGER DEFAULT 0,
  bytes_recv INTEGER DEFAULT 0, bad INTEGER DEFAULT 0, feed TEXT DEFAULT '',
  PRIMARY KEY (agent, dest, port)
);
CREATE TABLE IF NOT EXISTS alerts (
  agent TEXT, dest TEXT, ip TEXT, feed TEXT, indicator TEXT,
  first_seen INTEGER, last_seen INTEGER, times_seen INTEGER DEFAULT 0,
  PRIMARY KEY (agent, dest, feed)
);
CREATE TABLE IF NOT EXISTS dns (
  agent TEXT, via TEXT DEFAULT '', name TEXT, container TEXT DEFAULT '',
  first_seen INTEGER, last_seen INTEGER, times_seen INTEGER DEFAULT 0, flags TEXT DEFAULT '',
  PRIMARY KEY (agent, name)
);
CREATE TABLE IF NOT EXISTS execs (
  agent TEXT, via TEXT DEFAULT '', cmd TEXT, container TEXT DEFAULT '',
  first_seen INTEGER, last_seen INTEGER, times_seen INTEGER DEFAULT 0,
  PRIMARY KEY (agent, cmd)
);
CREATE TABLE IF NOT EXISTS installs (
  ts INTEGER, agent TEXT, via TEXT DEFAULT '', manager TEXT, packages TEXT, cmd TEXT, container TEXT DEFAULT '',
  flags TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS packages (
  root TEXT, manager TEXT, name TEXT, version TEXT, location TEXT,
  first_seen INTEGER, gone_at INTEGER, baseline INTEGER DEFAULT 0, agents TEXT DEFAULT '', flags TEXT DEFAULT '',
  PRIMARY KEY (root, manager, name, version, location)
);
CREATE TABLE IF NOT EXISTS blocks (
  ts INTEGER, agent TEXT, dest TEXT, ip TEXT, reason TEXT, feed TEXT, indicator TEXT, cmd TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS conns_agent ON conns(agent);
CREATE INDEX IF NOT EXISTS conns_bad ON conns(bad);
"""


def connect(path: str | None = None) -> sqlite3.Connection:
    db = sqlite3.connect(path or config.db_path())
    db.row_factory = sqlite3.Row
    db.executescript(_SCHEMA)
    return db


def record_agent(db: sqlite3.Connection, agent: str, ts: int) -> None:
    db.execute(
        """INSERT INTO agents(agent, first_seen, last_seen, samples) VALUES(?,?,?,1)
           ON CONFLICT(agent) DO UPDATE SET last_seen=excluded.last_seen, samples=samples+1""",
        (agent, ts, ts),
    )


def record_conn(db, agent, dest, ip, port, ts, bytes_recv, bad=False, feed="") -> None:
    db.execute(
        """INSERT INTO conns(agent,dest,ip,port,first_seen,last_seen,times_seen,bytes_recv,bad,feed)
           VALUES(?,?,?,?,?,?,1,?,?,?)
           ON CONFLICT(agent,dest,port) DO UPDATE SET
             last_seen=excluded.last_seen,
             times_seen=times_seen+1,
             bytes_recv=max(bytes_recv, excluded.bytes_recv),
             ip=excluded.ip,
             bad=max(bad, excluded.bad),
             feed=CASE WHEN excluded.bad=1 THEN excluded.feed ELSE feed END""",
        (agent, dest, ip, port, ts, ts, bytes_recv, int(bad), feed),
    )


def record_block(db, agent, dest, ip, reason, feed, indicator, cmd, ts) -> None:
    db.execute("INSERT INTO blocks(ts,agent,dest,ip,reason,feed,indicator,cmd) VALUES(?,?,?,?,?,?,?,?)",
               (ts, agent, dest, ip, reason, feed, indicator, cmd))


def blocks(db, limit: int = 100) -> list[dict]:
    return [dict(r) for r in db.execute("SELECT * FROM blocks ORDER BY ts DESC LIMIT ?", (limit,))]


def record_alert(db, agent, dest, ip, feed, indicator, ts) -> None:
    db.execute(
        """INSERT INTO alerts(agent,dest,ip,feed,indicator,first_seen,last_seen,times_seen)
           VALUES(?,?,?,?,?,?,?,1)
           ON CONFLICT(agent,dest,feed) DO UPDATE SET
             last_seen=excluded.last_seen, times_seen=times_seen+1""",
        (agent, dest, ip, feed, indicator, ts, ts),
    )


def agents(db) -> list[dict]:
    rows = db.execute(
        """SELECT a.agent, a.first_seen, a.last_seen, a.samples,
                  COUNT(DISTINCT c.dest) AS dests,
                  COALESCE(SUM(c.bytes_recv),0) AS bytes_recv,
                  COALESCE(SUM(c.bad),0) AS bad_dests
           FROM agents a LEFT JOIN conns c ON c.agent=a.agent
           GROUP BY a.agent ORDER BY a.last_seen DESC"""
    ).fetchall()
    return [dict(r) for r in rows]


def agent_conns(db, agent: str) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM conns WHERE agent=? ORDER BY bad DESC, bytes_recv DESC, last_seen DESC",
        (agent,),
    ).fetchall()
    return [dict(r) for r in rows]


def history(db, agent: str | None = None, bad_only: bool = False, limit: int = 500) -> list[dict]:
    q = "SELECT * FROM conns WHERE 1=1"
    args: list = []
    if agent:
        q += " AND agent=?"
        args.append(agent)
    if bad_only:
        q += " AND bad=1"
    q += " ORDER BY last_seen DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in db.execute(q, args).fetchall()]


def alerts(db, limit: int = 500) -> list[dict]:
    return [dict(r) for r in db.execute(
        "SELECT * FROM alerts ORDER BY last_seen DESC LIMIT ?", (limit,)
    ).fetchall()]


def baseline_reset(db) -> None:
    """Clear the learned baseline: drop connection + DNS + alert history so the box re-learns from scratch."""
    db.execute("delete from conns")
    db.execute("delete from dns")
    db.execute("delete from alerts")
    db.commit()


def baseline(db) -> list[tuple[str, str, int]]:
    """Every (agent, dest, port) recorded so far — the 'normal' history the anomaly watch seeds its baseline from."""
    return [(r["agent"], r["dest"], r["port"]) for r in db.execute(
        "SELECT agent, dest, port FROM conns"
    ).fetchall()]


def stats(db) -> dict:
    with closing(db.cursor()) as cur:
        n_agents = cur.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
        n_conns = cur.execute("SELECT COUNT(*) FROM conns").fetchone()[0]
        n_bad = cur.execute("SELECT COUNT(*) FROM conns WHERE bad=1").fetchone()[0]
        n_alerts = cur.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        last = cur.execute("SELECT MAX(last_seen) FROM agents").fetchone()[0]
    return {
        "agents": n_agents, "destinations": n_conns, "bad_destinations": n_bad,
        "alerts": n_alerts, "last_sample": last or 0, "now": int(time.time()),
    }


def record_dns(db, agent, via, name, container, ts, flags="") -> None:
    db.execute(
        """INSERT INTO dns(agent,via,name,container,first_seen,last_seen,times_seen,flags) VALUES(?,?,?,?,?,?,1,?)
           ON CONFLICT(agent,name) DO UPDATE SET last_seen=excluded.last_seen, times_seen=times_seen+1,
             via=excluded.via, flags=CASE WHEN excluded.flags!='' THEN excluded.flags ELSE flags END""",
        (agent, via, name, container, ts, ts, flags),
    )


def record_exec(db, agent, via, cmd, container, ts) -> None:
    db.execute(
        """INSERT INTO execs(agent,via,cmd,container,first_seen,last_seen,times_seen) VALUES(?,?,?,?,?,?,1)
           ON CONFLICT(agent,cmd) DO UPDATE SET last_seen=excluded.last_seen, times_seen=times_seen+1""",
        (agent, via, cmd[:500], container, ts, ts),
    )


def record_install(db, ts, agent, via, manager, packages, cmd, container, flags="") -> None:
    db.execute("INSERT INTO installs(ts,agent,via,manager,packages,cmd,container,flags) VALUES(?,?,?,?,?,?,?,?)",
               (ts, agent, via, manager, " ".join(packages), cmd[:500], container, flags))


def known_packages(db, root: str) -> set:
    return {(r["manager"], r["name"], r["version"], r["location"]) for r in db.execute(
        "SELECT manager,name,version,location FROM packages WHERE root=? AND gone_at IS NULL", (root,))}


def has_inventory(db, root: str) -> bool:
    return db.execute("SELECT 1 FROM packages WHERE root=? LIMIT 1", (root,)).fetchone() is not None


def add_packages(db, root, pkgs, ts, baseline=False, agents="") -> None:
    db.executemany(
        """INSERT INTO packages(root,manager,name,version,location,first_seen,gone_at,baseline,agents)
           VALUES(?,?,?,?,?,?,NULL,?,?)
           ON CONFLICT(root,manager,name,version,location) DO UPDATE SET gone_at=NULL""",
        [(root, m, n, v, loc, ts, int(baseline), agents) for m, n, v, loc in pkgs],
    )


def flag_package(db, root, pkg, flags) -> None:
    m, n, v, loc = pkg
    db.execute("UPDATE packages SET flags=? WHERE root=? AND manager=? AND name=? AND version=? AND location=?",
               (flags, root, m, n, v, loc))


def gone_packages(db, root, pkgs, ts) -> None:
    db.executemany(
        "UPDATE packages SET gone_at=? WHERE root=? AND manager=? AND name=? AND version=? AND location=?",
        [(ts, root, m, n, v, loc) for m, n, v, loc in pkgs],
    )


def recent_agents(db, since: int) -> list[str]:
    """Agents seen doing anything since `since`, busiest first (for "who was active when this appeared")."""
    rows = db.execute(
        """SELECT agent, SUM(n) AS n FROM (
             SELECT agent, COUNT(*) AS n FROM installs WHERE ts >= ? GROUP BY agent
             UNION ALL SELECT agent, 1 FROM execs WHERE last_seen >= ?
             UNION ALL SELECT agent, 1 FROM agents WHERE last_seen >= ?)
           GROUP BY agent ORDER BY n DESC LIMIT 5""", (since, since, since)).fetchall()
    return [r["agent"] for r in rows]


def installs(db, limit: int = 200) -> list[dict]:
    return [dict(r) for r in db.execute("SELECT * FROM installs ORDER BY ts DESC LIMIT ?", (limit,))]


def new_packages(db, limit: int = 200) -> list[dict]:
    return [dict(r) for r in db.execute(
        "SELECT * FROM packages WHERE baseline=0 ORDER BY first_seen DESC LIMIT ?", (limit,))]


def dns_names(db, agent: str | None = None, flagged: bool = False, limit: int = 500) -> list[dict]:
    q, a = "SELECT * FROM dns WHERE 1=1", []
    if agent:
        q += " AND agent=?"
        a.append(agent)
    if flagged:
        q += " AND flags!=''"
    q += " ORDER BY last_seen DESC LIMIT ?"
    a.append(limit)
    return [dict(r) for r in db.execute(q, a)]
