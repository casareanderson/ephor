"""`ephor query`: read-only SQL over everything Ephor has recorded, osquery-style.

    ephor query "SELECT agent, name, flags FROM dns WHERE flags != '' ORDER BY last_seen DESC"
    ephor query "SELECT agent, manager, packages FROM installs WHERE ts > strftime('%s','now','-1 day')"
    ephor query --schema

The database is opened read-only (SQLite `mode=ro`) and an authorizer refuses anything but reading, so a query
can't change history even by accident. Times are Unix seconds; `datetime(ts,'unixepoch')` makes them readable.
"""
from __future__ import annotations

import sqlite3

from . import config, store

_READ_OK = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
_RECURSIVE = getattr(sqlite3, "SQLITE_RECURSIVE", 33)


def _authorizer(action, *_):
    return sqlite3.SQLITE_OK if action in _READ_OK or action == _RECURSIVE else sqlite3.SQLITE_DENY


def connect_ro(path: str | None = None) -> sqlite3.Connection:
    path = path or config.db_path()
    store.connect(path).close()                       # make sure the tables exist (a fresh install has none)
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    db.set_authorizer(_authorizer)
    return db


def run(sql: str, path: str | None = None, limit: int = 1000) -> tuple[list[str], list[tuple]]:
    """(column names, rows). Raises sqlite3.Error with SQLite's message on a bad or non-read query."""
    db = connect_ro(path)
    try:
        cur = db.execute(sql)
        cols = [d[0] for d in cur.description or []]
        rows = [tuple(r) for r in cur.fetchmany(limit)]
        return cols, rows
    finally:
        db.close()


def schema(path: str | None = None) -> str:
    db = connect_ro(path)
    try:
        return "\n".join(r[0] + ";" for r in db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL ORDER BY name"))
    finally:
        db.close()


def table(cols: list[str], rows: list[tuple], width: int = 60) -> str:
    def cell(v) -> str:
        s = "" if v is None else str(v)
        return s if len(s) <= width else s[:width - 1] + "…"
    body = [[cell(v) for v in r] for r in rows]
    w = [max([len(c)] + [len(r[i]) for r in body]) for i, c in enumerate(cols)]
    lines = ["  ".join(c.ljust(w[i]) for i, c in enumerate(cols)).rstrip()]
    lines += ["  ".join(v.ljust(w[i]) for i, v in enumerate(r)).rstrip() for r in body]
    return "\n".join(lines)
