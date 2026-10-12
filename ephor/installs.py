"""What did an agent install? Two views that cover each other's gaps.

1. **Install commands** (`parse_command`): a command line like `pip install requests==2.19.0`, `npm i -g x`,
   `brew install y` or `curl https://... | sh` is recognised and its package names pulled out. This needs the
   command line, so it comes from the eBPF probe (`watch --ebpf`) or a lucky `/proc` sample.
2. **Inventory snapshots** (`snapshot` + `diff`): what is installed right now in the places package managers
   write to: Python site-packages (system, /usr/local, every user's ~/.local, pipx venvs), global npm, Homebrew,
   dpkg and apk. Comparing two snapshots catches every install however fast it ran, which a sampler can't.
   It reads directory names and small metadata files only; nothing is executed.

Both are passive: no package manager is run, nothing is blocked.
"""
from __future__ import annotations

import glob
import json
import os
import re
import shlex
from dataclasses import dataclass

# ---------------------------------------------------------------- install commands


@dataclass
class InstallCmd:
    manager: str            # pip, uv, pipx, npm, pnpm, yarn, bun, brew, apt, dnf, apk, cargo, go, gem, pipe-to-shell
    packages: list[str]     # names as typed (may carry a version: requests==2.19.0, left-pad@1.3.0)
    cmd: str


# manager -> (how to spot it in argv, the subcommands that install)
_SUBCMDS = {
    "pip": {"install"}, "uv": {"add", "install"}, "pipx": {"install", "inject", "run"},
    "npm": {"install", "i", "add", "exec", "x"}, "pnpm": {"add", "install", "i", "dlx"},
    "yarn": {"add", "dlx"}, "bun": {"add", "install", "i", "x"},
    "brew": {"install", "reinstall", "tap"}, "apt": {"install"}, "apt-get": {"install"},
    "dnf": {"install"}, "yum": {"install"}, "apk": {"add"}, "cargo": {"install", "add"},
    "go": {"install", "get"}, "gem": {"install"},
}
_ALWAYS = {"npx": "npm", "pnpx": "pnpm", "bunx": "bun", "uvx": "uv"}      # these fetch-and-run by definition
_SHELLS = {"sh", "bash", "dash", "zsh", "ash", "ksh", "busybox"}
_PIPE_SH = re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")
_FLAG_TAKES_VALUE = {"-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url", "-e",
                     "--editable", "-t", "--target", "--prefix", "--root", "-f", "--find-links", "--registry",
                     "--python", "-p", "--cwd", "-C"}


def _base(word: str) -> str:
    return os.path.basename(word)


def parse_command(cmd: str) -> InstallCmd | None:
    """Recognise one install command line, or None. Never raises."""
    if not cmd:
        return None
    first = _base(cmd.split(None, 1)[0])
    if first in _SHELLS and _PIPE_SH.search(cmd):           # a shell running the pipe, not a wrapper quoting it
        url = re.search(r"https?://[^\s'\"|;&]+", cmd)
        return InstallCmd("pipe-to-shell", [url.group(0) if url else "?"], cmd)
    try:
        argv = shlex.split(cmd)
    except ValueError:
        argv = cmd.split()
    if not argv:
        return None
    # python -m pip / python3 -m pip / uv pip install / sudo / env wrappers
    while argv and _base(argv[0]) in ("sudo", "env", "doas", "nice", "nohup", "time"):
        argv = [a for a in argv[1:] if "=" not in a or a.startswith("-")] if _base(argv[0]) == "env" else argv[1:]
    if not argv:
        return None
    head = _base(argv[0])
    rest = argv[1:]
    if re.fullmatch(r"python[0-9.]*", head) and len(rest) >= 2 and rest[0] == "-m":
        head, rest = rest[1], rest[2:]
    elif re.fullmatch(r"python[0-9.]*", head) and rest and _base(rest[0]) in ("pip", "pip3"):
        head, rest = "pip", rest[1:]                          # a venv's pip script run as `python .../bin/pip`
    head = re.sub(r"^pip[0-9.]*$", "pip", head)
    if head == "uv" and rest[:1] == ["pip"]:
        head, rest = "pip", rest[1:]
    if head in _ALWAYS:
        return InstallCmd(_ALWAYS[head], _names(rest)[:1], cmd)
    if head not in _SUBCMDS or not rest:
        return None
    sub = next((a for a in rest if not a.startswith("-")), "")
    if sub not in _SUBCMDS[head]:
        return None
    args = rest[rest.index(sub) + 1:]
    pk = _names(args)
    if head == "pipx" and sub == "run":
        pk = pk[:1]
    if not pk and head in ("npm", "pnpm", "yarn", "bun", "pip", "uv") and sub in ("install", "i"):
        pk = ["(from project file)"]                          # `npm install` / `pip install -r` with no names
    return InstallCmd("apt" if head == "apt-get" else "dnf" if head == "yum" else head, pk, cmd)


def _names(args: list[str]) -> list[str]:
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a in _FLAG_TAKES_VALUE:
            skip = True
            continue
        if a.startswith("-"):
            continue
        out.append(a)
    return out


def bare_name(spec: str) -> str:
    """requests==2.19.0 -> requests, left-pad@1.3.0 -> left-pad, @scope/pkg@1 -> @scope/pkg, user/tap/x -> x."""
    s = spec.strip()
    if s.startswith("@"):
        return "@" + re.split(r"@", s[1:], maxsplit=1)[0]
    s = re.split(r"[=<>!~\[;@ ]", s, maxsplit=1)[0]
    return s.rsplit("/", 1)[-1] if "/" in s and not s.startswith(("http", ".", "/")) else s


# ---------------------------------------------------------------- inventory snapshots

# A package as (manager, name, version, location). Location is the directory it lives in, so the same name in
# two virtualenvs is two packages.
Pkg = tuple[str, str, str, str]

_DIST = re.compile(r"^(?P<n>.+?)-(?P<v>[0-9][^-]*?)\.(dist-info|egg-info)$")


def _python_dirs(root: str) -> list[str]:
    pats = ["usr/lib/python3*/site-packages", "usr/lib/python3*/dist-packages", "usr/lib/python3/dist-packages",
            "usr/local/lib/python3*/site-packages", "usr/local/lib/python3*/dist-packages",
            "root/.local/lib/python3*/site-packages", "home/*/.local/lib/python3*/site-packages",
            "root/.local/share/pipx/venvs/*/lib/python3*/site-packages",
            "home/*/.local/share/pipx/venvs/*/lib/python3*/site-packages",
            "opt/*/lib/python3*/site-packages", "opt/*/venv/lib/python3*/site-packages",
            "opt/*/.venv/lib/python3*/site-packages",
            "home/linuxbrew/.linuxbrew/lib/python3*/site-packages", "opt/homebrew/lib/python3*/site-packages"]
    out: list[str] = []
    for p in pats:
        out += glob.glob(os.path.join(root, p))
    return sorted(set(out))


def _python(root: str) -> set[Pkg]:
    pk: set[Pkg] = set()
    for d in _python_dirs(root):
        try:
            names = os.listdir(d)
        except OSError:
            continue
        loc = "/" + os.path.relpath(d, root)
        for n in names:
            m = _DIST.match(n)
            if m:
                pk.add(("pypi", m.group("n").replace("_", "-").lower(), m.group("v"), loc))
    return pk


def _npm(root: str) -> set[Pkg]:
    pk: set[Pkg] = set()
    for d in ("usr/lib/node_modules", "usr/local/lib/node_modules", "root/.npm-global/lib/node_modules",
              "home/*/.npm-global/lib/node_modules", "opt/homebrew/lib/node_modules",
              "home/linuxbrew/.linuxbrew/lib/node_modules"):
        for nm in glob.glob(os.path.join(root, d)):
            loc = "/" + os.path.relpath(nm, root)
            for pj in glob.glob(os.path.join(nm, "*", "package.json")) + glob.glob(os.path.join(nm, "@*", "*",
                                                                                                "package.json")):
                try:
                    with open(pj) as f:
                        j = json.load(f)
                    pk.add(("npm", str(j.get("name") or ""), str(j.get("version") or ""), loc))
                except (OSError, ValueError, AttributeError):
                    continue
    return {p for p in pk if p[1]}


def _brew(root: str) -> set[Pkg]:
    pk: set[Pkg] = set()
    for cellar in ("home/linuxbrew/.linuxbrew/Cellar", "opt/homebrew/Cellar", "usr/local/Cellar"):
        for v in glob.glob(os.path.join(root, cellar, "*", "*")):
            pk.add(("brew", os.path.basename(os.path.dirname(v)), os.path.basename(v), "/" + cellar))
    return pk


def _dpkg(root: str) -> set[Pkg]:
    pk: set[Pkg] = set()
    try:
        with open(os.path.join(root, "var/lib/dpkg/status"), errors="replace") as f:
            text = f.read()
    except OSError:
        return pk
    for block in text.split("\n\n"):
        name = ver = status = ""
        for line in block.splitlines():
            if line.startswith("Package: "):
                name = line[9:].strip()
            elif line.startswith("Version: "):
                ver = line[9:].strip()
            elif line.startswith("Status: "):
                status = line[8:]
        if name and status.endswith("installed") and "not-installed" not in status:
            pk.add(("dpkg", name, ver, "/var/lib/dpkg"))
    return pk


def _apk(root: str) -> set[Pkg]:
    pk: set[Pkg] = set()
    try:
        with open(os.path.join(root, "lib/apk/db/installed"), errors="replace") as f:
            text = f.read()
    except OSError:
        return pk
    for block in text.split("\n\n"):
        f = {line[0]: line[2:] for line in block.splitlines() if len(line) > 2 and line[1] == ":"}
        if f.get("P"):
            pk.add(("apk", f["P"], f.get("V", ""), "/lib/apk/db"))
    return pk


def snapshot(root: str = "/") -> set[Pkg]:
    """Everything installed under `root` that Ephor knows how to read. Cheap: directory listings + 2 db files."""
    return _python(root) | _npm(root) | _brew(root) | _dpkg(root) | _apk(root)


def diff(old: set[Pkg], new: set[Pkg]) -> tuple[list[Pkg], list[Pkg]]:
    """(added, removed). An upgrade shows as one of each, which is what you want to see."""
    return sorted(new - old), sorted(old - new)
