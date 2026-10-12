"""Who started this process? Walk the parent chain up to an agent Ephor recognises.

A coding agent rarely talks to PyPI itself: it runs `pip install`, which runs a python, which opens the socket.
Classified on its own that process is just `py:pip` or `other:curl`. Walking `/proc/<pid>/stat` parents until a
*named* agent turns up (hermes, opencode, claude, cursor, a user-configured pattern...) turns it into
`opencode` via `py:pip`, which is the answer you actually want.

Short-lived processes are often gone by the time anyone looks, so the resolver also keeps what the eBPF probe
told it (pid -> parent, command line) and falls back to that when `/proc` no longer has the pid.
"""
from __future__ import annotations

import os

from . import classify

MAX_DEPTH = 24
_GENERIC = ("other:", "py:", "node")


def is_named(label: str) -> bool:
    """A label that names an agent, as opposed to the generic python/node/other fallbacks."""
    return bool(label) and not label.startswith(_GENERIC)


def _read(path: str) -> str:
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def parse_stat_ppid(stat: str) -> int:
    """The parent pid from a /proc/<pid>/stat line. The command name is in parentheses and may itself contain
    spaces or ')', so split on the LAST ')'."""
    try:
        return int(stat.rsplit(")", 1)[1].split()[1])
    except (IndexError, ValueError):
        return 0


def _via(cmd: str, own: str) -> str:
    """How the agent did it: the package manager for an install (`pip`, `npm`, `pipe-to-shell`), else the
    process's own label."""
    from . import installs
    ic = installs.parse_command(cmd)
    return ic.manager if ic else own


class Resolver:
    """Resolve pid -> (agent, via). `proc` is the /proc root (tests point it at a fake tree)."""

    def __init__(self, proc: str = "/proc", remember: int = 20000) -> None:
        self.proc = proc
        self.known: dict[int, tuple[int, str, str]] = {}      # pid -> (ppid, cmdline, exe), from probe events
        self.remember = remember

    def note(self, pid: int, ppid: int, cmd: str, exe: str = "") -> None:
        """Record what the probe saw at exec time, so the chain survives the process exiting."""
        if len(self.known) >= self.remember:                    # keep memory bounded on a busy box
            for k in list(self.known)[: self.remember // 4]:
                del self.known[k]
        self.known[pid] = (ppid, cmd, exe)

    def info(self, pid: int) -> tuple[int, str, str] | None:
        """(ppid, cmdline, exe) for a pid, live /proc first, then what the probe recorded."""
        stat = _read(f"{self.proc}/{pid}/stat")
        if stat:
            cmd = _read(f"{self.proc}/{pid}/cmdline").replace("\x00", " ").strip()
            try:
                exe = os.readlink(f"{self.proc}/{pid}/exe")
            except OSError:
                exe = ""
            if cmd or pid not in self.known:
                return parse_stat_ppid(stat), cmd, exe
        return self.known.get(pid)

    def chain(self, pid: int) -> list[tuple[int, str, str]]:
        """[(pid, cmdline, exe)] from pid up towards init (pid itself first)."""
        out, seen = [], set()
        while pid > 1 and pid not in seen and len(out) < MAX_DEPTH:
            seen.add(pid)
            i = self.info(pid)
            if not i:
                break
            ppid, cmd, exe = i
            out.append((pid, cmd, exe))
            pid = ppid
        return out

    def descends_from(self, pid: int, ancestor: int) -> bool:
        return any(p == ancestor for p, _, _ in self.chain(pid))

    def resolve(self, pid: int, cmd: str = "", exe: str = "") -> tuple[str, str]:
        """(agent, via). `via` is the process's own label when an ancestor agent was found ('' otherwise).

        An ignored ancestor (sshd, systemd, cron) ends the walk: a shell someone logged into is a person, not an
        agent. The process itself is always labelled, so nothing goes unreported."""
        own = classify.classify(cmd, exe) if cmd or exe else ""
        links = self.chain(pid)
        if not own and links:
            own = classify.classify(links[0][1], links[0][2])
        if is_named(own):
            return own, ""
        for _, pcmd, pexe in links[1:]:
            label = classify.classify(pcmd, pexe)
            if is_named(label):
                return label, _via(cmd or (links[0][1] if links else ""), own)
            if classify.ignored(pcmd):
                break
        return own or "other:unknown", ""
