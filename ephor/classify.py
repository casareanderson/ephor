"""Attribute a process to an *agent* — generically and configurably.

The goal is to turn a raw process (command line, executable, owning user) into a stable agent label like
``hermes:coder``, ``claude``, ``ollama`` or ``langchain:myscript``. None of this is hard-coded to one estate:
built-in patterns cover the common AI runtimes, a config file adds your own, and anything unrecognised still
gets a deterministic ``other:<exe>`` label so nothing slips through unseen.

Classification order:
  1. user-supplied patterns from config  (``[[agents]] pattern = "...", name = "..."``)
  2. built-in named runtimes             (claude, cursor, ollama, the python LLM frameworks, node agents, ...)
  3. python fallback                     (``python -m pkg`` -> ``py:pkg``;  ``python foo.py`` -> ``py:foo``)
  4. last resort                         (``other:<basename of exe>``)

The ignore list drops things that are never an "AI agent doing something" — sshd, systemd, cron, the kernel,
and (by default) Claude Code itself, so Ephor never reports on the tool you are reading this with.
"""
from __future__ import annotations

import os
import re

from . import config

# Command lines we never track. Entries are substrings, or /regex/ when wrapped in slashes.
IGNORE_DEFAULT = [
    r"/(^|/)sshd?\b/",
    r"/\bsystemd(-\w+)?\b/",
    r"/(^|/)(cron|crond|dbus-daemon|rsyslogd|chronyd|agetty|login)\b/",
    r"/\bclaude-code\b/",
    r"@anthropic-ai/claude-code",
    # mesh/VPN and monitoring daemons: real egress, but not AI agents — pure noise. Override via config if wanted.
    r"/\b(tailscaled|netbird|wireguard|zerotier-one)\b/",
    r"/\b(node_exporter|beszel-agent|beszel|prometheus|telegraf|netdata)\b/",
]

# (compiled cmdline regex, label)  — tried in order. {g1} means "use the first capture group, basename-ised".
_BUILTINS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bhermes\b.*?--profile[= ]+(\S+)"), "hermes:{g1}"),
    (re.compile(r"\bhermes\b"), "hermes"),
    (re.compile(r"\bopencode\b"), "opencode"),
    (re.compile(r"\bollama\b"), "ollama"),
    (re.compile(r"@anthropic-ai/claude\b|\bclaude-desktop\b"), "claude"),
    (re.compile(r"\bcursor\b|\bcursor-server\b"), "cursor"),
    (re.compile(r"\bchatgpt\b|\bchatgpt-desktop\b"), "chatgpt-desktop"),
    (re.compile(r"\b(aider)\b"), "aider"),
    (re.compile(r"\b(crawl4ai|playwright|puppeteer)\b"), "scraper"),
    # python LLM frameworks: label by the framework so many scripts collapse to one agent
    (re.compile(r"\b(langchain|langgraph)\b"), "langchain"),
    (re.compile(r"\bcrewai\b"), "crewai"),
    (re.compile(r"\b(autogen|pyautogen|ag2)\b"), "autogen"),
    (re.compile(r"\bllama_index\b|\bllama-index\b"), "llamaindex"),
    (re.compile(r"\bsemantic_kernel\b"), "semantic-kernel"),
    (re.compile(r"\bhaystack\b"), "haystack"),
]

_PY = re.compile(r"\bpython[0-9.]*\b")
_PY_M = re.compile(r"-m[= ]+([A-Za-z0-9_.]+)")
_PY_FILE = re.compile(r"(\S+\.py)\b")
_NODE = re.compile(r"\bnode\b")


def _ignore_patterns() -> list:
    out = []
    for raw in IGNORE_DEFAULT + list(config.CONF.get("ignore") or []):
        if len(raw) >= 2 and raw[0] == "/" and raw[-1] == "/":
            try:
                out.append(("re", re.compile(raw[1:-1])))
            except re.error:
                continue
        else:
            out.append(("sub", raw))
    return out


_IGNORE = _ignore_patterns()


def _user_patterns() -> list[tuple[re.Pattern, str]]:
    out = []
    for item in config.CONF.get("agents") or []:
        pat, name = item.get("pattern"), item.get("name")
        if pat and name:
            try:
                out.append((re.compile(pat), name))
            except re.error:
                continue
    return out


_USER = _user_patterns()


def ignored(cmd: str) -> bool:
    for kind, pat in _IGNORE:
        if kind == "sub" and pat in cmd:
            return True
        if kind == "re" and pat.search(cmd):
            return True
    return False


def _apply(label: str, m: re.Match) -> str:
    if "{g1}" in label:
        g = (m.group(1) if m.groups() else "") or ""
        g = os.path.basename(g.strip("/")) or "default"
        return label.replace("{g1}", g)
    return label


def classify(cmd: str, exe: str = "") -> str:
    """Map a command line (and optional exe path) to an agent label. Never raises."""
    cmd = (cmd or "").strip()
    for pat, label in _USER:
        m = pat.search(cmd)
        if m:
            return _apply(label, m)
    for pat, label in _BUILTINS:
        m = pat.search(cmd)
        if m:
            return _apply(label, m)
    if _PY.search(cmd) or (exe and "python" in os.path.basename(exe)):
        m = _PY_M.search(cmd)
        if m:
            return "py:" + m.group(1).split(".")[0]
        m = _PY_FILE.search(cmd)
        if m:
            return "py:" + os.path.splitext(os.path.basename(m.group(1)))[0]
        return "py:repl"
    if _NODE.search(cmd) or (exe and os.path.basename(exe) in ("node", "nodejs")):
        m = _PY_FILE.search(cmd.replace(".py", ".js")) or re.search(r"(\S+\.(?:js|mjs|cjs|ts))\b", cmd)
        if m:
            return "node:" + os.path.splitext(os.path.basename(m.group(1)))[0]
        return "node"
    base = os.path.basename(exe) if exe else (cmd.split() or ["unknown"])[0]
    base = os.path.basename(base.strip("/")) or "unknown"
    return "other:" + base
