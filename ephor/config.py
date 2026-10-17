"""Configuration and paths. Config is optional: Ephor works with sensible defaults out of the box.

Looked for, first that exists wins:
  $EPHOR_CONFIG, ./ephor.toml, ~/.config/ephor/ephor.toml, /etc/ephor/ephor.toml

Keys (all optional):
  data_dir        where the history DB and feed cache live (default ~/.local/share/ephor, or /var/lib/ephor as root)
  agents          [{pattern = "<regex on the command line>", name = "<label>"}]  extra classifiers (tried first)
  ignore          ["<substring>", "/<regex>/"]  command lines never tracked (added to the built-in ignore list)
  secret_paths    ["~/.env", "/run/secrets", ...]  files/dirs the permissions view checks each agent can read
  feeds           {urlhaus = true, feodo = true, firehol = true, threatfox = false}  which threat feeds to use
  feed_ttl_hours  how long a cached feed is reused before refetching (default 12)
"""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

_SEARCH = [
    os.environ.get("EPHOR_CONFIG"),
    "ephor.toml",
    os.path.expanduser("~/.config/ephor/ephor.toml"),
    "/etc/ephor/ephor.toml",
]


def _load() -> dict:
    for p in _SEARCH:
        if p and Path(p).is_file():
            try:
                with open(p, "rb") as f:
                    return tomllib.load(f)
            except (OSError, tomllib.TOMLDecodeError):
                return {}
    return {}


CONF = _load()


def data_dir() -> Path:
    d = CONF.get("data_dir")
    if not d:
        d = "/var/lib/ephor" if os.geteuid() == 0 else os.path.expanduser("~/.local/share/ephor")
    d = os.environ.get("EPHOR_DATA", d)
    Path(d).mkdir(parents=True, exist_ok=True)
    return Path(d)


def db_path() -> str:
    return str(data_dir() / "ephor.db")


def secret_paths() -> list[str]:
    return [os.path.expanduser(p) for p in (CONF.get("secret_paths") or [])]


def block_pipe_to_shell() -> bool:
    """Whether `curl … | sh` is killed as well as alerted. On by default."""
    return bool(CONF.get("block_pipe_to_shell", True))


def quarantine_dir() -> str:
    """Where pipe-to-shell payloads are written for inspection. Default: <data_dir>/quarantine."""
    d = CONF.get("quarantine_dir")
    if not d:
        d = str(data_dir() / "quarantine")
    return d


def feeds_enabled() -> dict:
    f = {"urlhaus": True, "feodo": True, "firehol": True, "threatfox": False}
    f.update({k: bool(v) for k, v in (CONF.get("feeds") or {}).items()})
    return f


def feed_ttl_hours() -> int:
    try:
        return int(CONF.get("feed_ttl_hours", 12))
    except (TypeError, ValueError):
        return 12


def alert() -> dict:
    """Settings for the opt-in `watch --loop` anomaly watch (all optional)."""
    d = {
        "warmup_seconds": 60,          # learn the per-agent baseline quietly, then start alerting
        "large_transfer_bytes": 1048576,  # a 'new' destination only alerts once it pulls at least 1 MB
        "webhook": "",                 # optional Discord/Slack/generic JSON alert sink
        "syslog": False,               # also emit alerts to syslog
    }
    d.update({k: v for k, v in (CONF.get("alert") or {}).items()})
    return d
