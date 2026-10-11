"""History — a tiny SQLite file (stdlib `sqlite3`, no server, no ORM).

Each `watch` sample is folded into three tables:

  agents        one row per agent label: first/last seen, how many samples it appeared in
  conns         one row per (agent, dest, port): first/last seen, sample count, bytes received, bad flag
  alerts        one row per (agent, dest, feed) when a destination matched a threat feed

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
