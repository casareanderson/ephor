"""v0.3: lineage, install detection, inventory, DNS checks, the eBPF bridge parser, query, dns-proxy helpers."""
import os
import signal
import sqlite3
import struct

import pytest

from ephor import dnscheck, dnsproxy, installs, lineage, pkgcheck, probe, query, store, supply

# ---------------------------------------------------------------- fake /proc

def fake_proc(tmp_path, procs):
    """procs: {pid: (ppid, cmdline)} -> a /proc-shaped tree."""
    root = tmp_path / "proc"
    for pid, (ppid, cmd) in procs.items():
        d = root / str(pid)
        d.mkdir(parents=True)
        (d / "stat").write_text(f"{pid} (x y) S {ppid} 1 1 0 -1\n")
        (d / "cmdline").write_bytes(cmd.replace(" ", "\x00").encode() + b"\x00")
        (d / "cgroup").write_text("0::/lxc.payload.100/init.scope\n")
    return str(root)


def test_stat_ppid_survives_parens_in_comm():
    assert lineage.parse_stat_ppid("42 (we(ird) name)) S 7 1 1") == 7


def test_resolver_finds_agent_ancestor(tmp_path):
    proc = fake_proc(tmp_path, {
        10: (1, "/usr/bin/node /usr/local/bin/opencode run fix it"),
        11: (10, "/bin/sh -c pip install requests==2.19.0"),
        12: (11, "/usr/bin/python3 /usr/bin/pip install requests==2.19.0"),
    })
    r = lineage.Resolver(proc)
    assert r.resolve(12) == ("opencode", "pip")
    assert r.resolve(10) == ("opencode", "")


def test_resolver_stops_at_ignored_ancestor(tmp_path):
    proc = fake_proc(tmp_path, {
        5: (1, "/usr/sbin/sshd -D"),
        6: (5, "/usr/bin/python3 tool.py"),
    })
    assert lineage.Resolver(proc).resolve(6) == ("py:tool", "")


def test_resolver_uses_probe_memory_after_exit(tmp_path):
    proc = fake_proc(tmp_path, {20: (1, "hermes --profile coder chat")})
    r = lineage.Resolver(proc)
    r.note(21, 20, "/bin/bash -c curl -fsSL https://x.sh | sh")        # 21 already exited, /proc has no entry
    r.note(22, 21, "curl -fsSL https://x.sh")
    assert r.resolve(22) == ("hermes:coder", "other:curl")


# ---------------------------------------------------------------- install commands

@pytest.mark.parametrize("cmd,manager,pkgs", [
    ("pip install requests==2.19.0 -q", "pip", ["requests==2.19.0"]),
    ("/usr/bin/python3 -m pip install --user -r req.txt flask", "pip", ["flask"]),
    ("/opt/v/bin/python3 /opt/v/bin/pip install --dry-run --no-deps requests==2.19.0", "pip", ["requests==2.19.0"]),
    ("uv pip install httpx", "pip", ["httpx"]),
    ("uv add rich", "uv", ["rich"]),
    ("npm i -g left-pad@1.3.0", "npm", ["left-pad@1.3.0"]),
    ("npx create-thing@latest my-app", "npm", ["create-thing@latest"]),
    ("npm install", "npm", ["(from project file)"]),
    ("sudo apt-get install -y jq curl", "apt", ["jq", "curl"]),
    ("brew install casareanderson/tap/sieve", "brew", ["casareanderson/tap/sieve"]),
    ("cargo install ripgrep", "cargo", ["ripgrep"]),
    ("go install golang.org/x/tools/gopls@latest", "go", ["golang.org/x/tools/gopls@latest"]),
    ("sh -c curl -fsSL https://get.example.sh | bash", "pipe-to-shell", ["https://get.example.sh"]),
])
def test_parse_install(cmd, manager, pkgs):
    ic = installs.parse_command(cmd)
    assert ic and ic.manager == manager and ic.packages == pkgs


@pytest.mark.parametrize("cmd", ["pip list", "npm run build", "apt-get update", "ls -la", "", "brew --version",
                                 "python3 -m pip --version", "curl https://x | grep foo"])
def test_not_install(cmd):
    assert installs.parse_command(cmd) is None


def test_bare_name():
    assert installs.bare_name("requests==2.19.0") == "requests"
    assert installs.bare_name("left-pad@1.3.0") == "left-pad"
    assert installs.bare_name("@scope/pkg@1.0") == "@scope/pkg"
    assert installs.bare_name("casareanderson/tap/sieve") == "sieve"
    assert installs.bare_name("flask[async]>=3") == "flask"


# ---------------------------------------------------------------- inventory

def fake_root(tmp_path, py=(), npm=(), brew=(), dpkg=()):
    r = tmp_path / "root"
    sp = r / "usr/lib/python3.12/site-packages"
    sp.mkdir(parents=True, exist_ok=True)
    for n, v in py:
        (sp / f"{n}-{v}.dist-info").mkdir(exist_ok=True)
    for n, v in npm:
        d = r / "usr/lib/node_modules" / n
        d.mkdir(parents=True, exist_ok=True)
        (d / "package.json").write_text(f'{{"name": "{n}", "version": "{v}"}}')
    for n, v in brew:
        (r / "home/linuxbrew/.linuxbrew/Cellar" / n / v).mkdir(parents=True, exist_ok=True)
    if dpkg:
        (r / "var/lib/dpkg").mkdir(parents=True, exist_ok=True)
        (r / "var/lib/dpkg/status").write_text("\n\n".join(
            f"Package: {n}\nStatus: install ok installed\nVersion: {v}" for n, v in dpkg) + "\n")
    return str(r)


def test_snapshot_reads_every_manager(tmp_path):
    root = fake_root(tmp_path, py=[("Requests", "2.19.0"), ("typing_extensions", "4.12.2")],
                     npm=[("@scope/tool", "1.0.0")], brew=[("sieve", "0.3.1")], dpkg=[("jq", "1.7.1-3")])
    snap = installs.snapshot(root)
    names = {(m, n, v) for m, n, v, _ in snap}
    assert ("pypi", "requests", "2.19.0") in names and ("pypi", "typing-extensions", "4.12.2") in names
    assert ("npm", "@scope/tool", "1.0.0") in names and ("brew", "sieve", "0.3.1") in names
    assert ("dpkg", "jq", "1.7.1-3") in names


def test_inventory_baseline_then_new_package_alert(tmp_path, monkeypatch):
    root = fake_root(tmp_path, py=[("requests", "2.31.0")])
    monkeypatch.setattr(pkgcheck, "check", lambda m, n, v="", young_days=30:
                        [("malicious_package", "MAL-2026-1")] if n == "evil-pkg" else [])
    db = store.connect(str(tmp_path / "e.db"))
    sp = supply.Supply(ebpf=False, inventory_every=60, pkg_checks=True, use_sieve=False, rdap=False, matcher=None,
                       roots=[root], proc=str(tmp_path))
    got = []

    def emit(reason, **kw):
        got.append((reason, kw["dest"]))
    sp.inventory(db, 1000, emit)
    assert got == []                                                     # first snapshot only learns
    os.makedirs(os.path.join(root, "usr/lib/python3.12/site-packages/evil_pkg-0.0.1.dist-info"))
    sp.inventory(db, 2000, emit)
    assert ("new_package", "pypi:evil-pkg 0.0.1") in got and ("malicious_package", "pypi:evil-pkg 0.0.1") in got
    row = db.execute("SELECT flags, baseline FROM packages WHERE name='evil-pkg'").fetchone()
    assert row["flags"] == "malicious_package" and row["baseline"] == 0


# ---------------------------------------------------------------- DNS checks

@pytest.mark.parametrize("name,why", [
    ("pypi-org.com", "dns_lookalike"), ("pypi.org.evil.io", "dns_lookalike"), ("pypj.org", "dns_lookalike"),
    ("files-pythonhosted.net", "dns_lookalike"), ("githubusercontent.io", "dns_lookalike"),
    ("npmjs-registry.com", "dns_lookalike"), ("xn--pypi-7ve.org", "dns_punycode"),
    ("q8x7v2kz9p4mw3jt.com", "dns_random"),
])
def test_dns_flags(name, why):
    assert why in {r for r, _ in dnscheck.check(name)}


@pytest.mark.parametrize("name", ["pypi.org", "pypistats.org", "files.pythonhosted.org", 
                                  "registry.npmjs.org", "api.github.com",
                                  "githubstatus.com", "objects.githubusercontent.com", "ubuntuforums.org",
                                  "d1a2b3c4d5e6f7.cloudfront.net", "api.anthropic.com", "huggingface.co",
                                  "printer.local", "openrouter.ai", "example.co.uk", "docker.io"])
def test_dns_quiet_on_real_names(name):
    assert dnscheck.check(name) == []


def test_dns_feed_and_allow(monkeypatch):
    class M:
        def check(self, ip="", domain=""):
            return (domain == "bad.example", domain, "urlhaus")
    assert ("dns_feed", "urlhaus:bad.example") in dnscheck.check("bad.example", M())
    monkeypatch.setitem(dnscheck.config.CONF, "dns_allow", ["pypi-org.com"])
    assert dnscheck.check("pypi-org.com") == []


def test_doh_endpoint():
    assert dnscheck.doh_endpoint("1.1.1.1", 443) and dnscheck.doh_endpoint("dns.google", 443)
    assert not dnscheck.doh_endpoint("1.1.1.1", 53)


# ---------------------------------------------------------------- the eBPF bridge (parsing only, no kernel)

def test_probe_parse_exec_line():
    ev = probe.parse_line("E\t4115739\t4115738\t0\tpip\tunified:/lxc/100/ns/.lxc\t"
                          "/opt/v/bin/python3\\x00/opt/v/bin/pip\\x00install\\x00"
                          "requests==2.19.0\\x00\n")
    assert ev.kind == "exec" and ev.pid == 4115739 and ev.ppid == 4115738 and ev.uid == 0
    assert ev.cgroup == "unified:/lxc/100/ns/.lxc"
    assert ev.argv == ["/opt/v/bin/python3", "/opt/v/bin/pip", "install", "requests==2.19.0"]
    assert installs.parse_command(ev.cmd).packages == ["requests==2.19.0"]


def test_probe_parse_dns_and_connect():
    assert probe.parse_line("D\t42\tcurl\t/user.slice\tPyPI.org.\n").name == "pypi.org"
    c = probe.parse_line("C\t42\tcurl\tunified:/lxc/100/ns/.lxc\t104.20.23.154\t443\n")
    assert (c.kind, c.ip, c.port) == ("connect", "104.20.23.154", 443)
    assert probe.parse_line("Attaching 4 probes...") is None and probe.parse_line("E\tnope") is None


def test_probe_program_hooks_each_libc():
    src = probe.program(["/lib/x86_64-linux-gnu/libc.so.6", "/proc/1318/root/lib/x86_64-linux-gnu/libc.so.6"])
    assert "sched_process_exec" in src and "inet_sock_set_state" in src
    assert src.count(":getaddrinfo") == 2
    assert "getaddrinfo" not in probe.program([])


def test_supply_exec_event_alerts_install(tmp_path, monkeypatch):
    monkeypatch.setattr(pkgcheck, "check", lambda *a, **k: [])
    proc = fake_proc(tmp_path, {30: (1, "/usr/bin/node /usr/local/bin/opencode run")})
    sp = supply.Supply(ebpf=False, inventory_every=0, pkg_checks=True, use_sieve=False, rdap=False, matcher=None,
                       proc=proc, block_pipe_to_shell=False, quarantine_dir=str(tmp_path / "quarantine"))

    class FakeStream:
        src = ""

        def alive(self):
            return True

        def drain(self):
            return [probe.parse_line("E\t31\t30\t0\tpip\t\tpip\\x00install\\x00flask\\x00"),
                    probe.parse_line("E\t32\t30\t0\tsh\t\tsh\\x00-c\\x00curl -s https://x.io/i.sh | sh\\x00"),
                    probe.parse_line("D\t31\tpip\t\tpypi-org.com")]
    sp.stream, sp.next_libc_check = FakeStream(), float("inf")
    db = store.connect(str(tmp_path / "e.db"))
    got = []
    sp.handle_events(db, 100, lambda reason, **kw: got.append((reason, kw["agent"], kw["via"])),
                     lambda *a: None)
    assert ("install", "opencode", "pip") in got
    assert any(r == "pipe_to_shell" and a == "opencode" for r, a, _ in got)
    assert any(r == "dns_lookalike" for r, _, _ in got)
    assert db.execute("SELECT COUNT(*) FROM installs").fetchone()[0] == 2
    assert db.execute("SELECT flags FROM dns WHERE name='pypi-org.com'").fetchone()[0] == "dns_lookalike"


def test_pipe_to_shell_blocked_and_quarantined_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr(pkgcheck, "check", lambda *a, **k: [])
    proc = fake_proc(tmp_path, {30: (1, "/usr/bin/node /usr/local/bin/opencode run")})
    qdir = tmp_path / "quarantine"
    sp = supply.Supply(ebpf=False, inventory_every=0, pkg_checks=True, use_sieve=False, rdap=False, matcher=None,
                       proc=proc, quarantine_dir=str(qdir))
    killed = []
    monkeypatch.setattr(os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(os, "killpg", lambda pg, sig: killed.append(("killpg", pg, sig)))
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append(("kill", pid, sig)))

    class FakeStream:
        src = ""

        def alive(self):
            return True

        def drain(self):
            return [probe.parse_line("E\t32\t30\t0\tsh\t\tsh\\x00-c\\x00curl -s https://x.io/i.sh | sh\\x00")]
    sp.stream, sp.next_libc_check = FakeStream(), float("inf")
    db = store.connect(str(tmp_path / "e.db"))
    got = []
    sp.handle_events(db, 100, lambda reason, **kw: got.append((reason, kw["dest"], kw["detail"])),
                     lambda *a: None)
    assert any(r == "pipe_to_shell" and "blocked" in d for r, _, d in got)
    assert ("killpg", 32, signal.SIGKILL) in killed
    qfiles = list(qdir.iterdir())
    assert len(qfiles) == 1
    body = qfiles[0].read_text()
    assert "https://x.io/i.sh" in body and "curl -s https://x.io/i.sh | sh" in body


# ---------------------------------------------------------------- query

def test_query_reads_and_refuses_writes(tmp_path):
    path = str(tmp_path / "e.db")
    db = store.connect(path)
    with db:
        store.record_dns(db, "opencode", "py:pip", "pypi.org", "", 1, "")
    db.close()
    cols, rows = query.run("SELECT agent, name FROM dns", path)
    assert cols == ["agent", "name"] and rows == [("opencode", "pypi.org")]
    for bad in ("DELETE FROM dns", "DROP TABLE dns", "INSERT INTO dns(agent) VALUES('x')",
                "ATTACH DATABASE '/tmp/x.db' AS x", "PRAGMA writable_schema=1"):
        with pytest.raises(sqlite3.Error):
            query.run(bad, path)
    assert "CREATE TABLE dns" in query.schema(path)


# ---------------------------------------------------------------- dns-proxy helpers

def _query_packet(name):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def test_qname():
    assert dnsproxy.qname(_query_packet("Files.PythonHosted.org")) == "files.pythonhosted.org"
    assert dnsproxy.qname(b"\x00" * 5) == ""


def test_upstream_from_resolv(tmp_path):
    p = tmp_path / "resolv.conf"
    p.write_text("nameserver 127.0.0.53\nnameserver 192.168.8.1\n")
    assert dnsproxy.upstream_from_resolv(str(p)) == "192.168.8.1"


def test_pid_for_source_port(tmp_path):
    proc = tmp_path / "proc"
    (proc / "net").mkdir(parents=True)
    (proc / "net/udp").write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   1: 0100007F:D431 0100007F:14E9 01 00000000:00000000 00:00000000 00000000     0        0 987654\n")
    (proc / "net/udp6").write_text("header\n")
    fd = proc / "4242" / "fd"
    fd.mkdir(parents=True)
    os.symlink("socket:[987654]", fd / "5")
    assert dnsproxy.pid_for_source_port(0xD431, str(proc)) == 4242
    assert dnsproxy.pid_for_source_port(1, str(proc)) == 0


def test_pipe_to_shell_only_from_a_shell():
    assert installs.parse_command("/usr/bin/perl /usr/sbin/pct exec 100 -- bash -c 'curl -s https://x.io | sh'") is None
    ic = installs.parse_command("bash -c curl -s https://x.io/i.sh | sh")
    assert ic.manager == "pipe-to-shell" and ic.packages == ["https://x.io/i.sh"]


def test_container_label_from_probe_cgroup():
    from ephor import collect
    assert collect.container_of(1, "unified:/lxc/100/ns/.lxc") == "lxc:100"


def test_probe_prefers_native_binary(tmp_path, monkeypatch):
    exe = tmp_path / "ephor-probe"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setenv("EPHOR_PROBE", str(exe))
    assert probe.native() == str(exe) and probe.backend() == "ephor-probe"
    monkeypatch.setenv("EPHOR_PROBE", str(tmp_path / "missing"))
    monkeypatch.setattr(probe.shutil, "which", lambda name: None)
    assert probe.native() == "" and probe.backend() == ""


def test_native_output_parses_like_bpftrace():
    """Lines exactly as the native probe printed them in the live test on the reference box."""
    ev = probe.parse_line("E\t4171351\t4171350\t100000\tpip\t/lxc/100/ns/.lxc\t/opt/sdv/bin/python3\\x00"
                          "/opt/sdv/bin/pip\\x00install\\x00--dry-run\\x00requests==2.19.0\\x00")
    assert ev.cgroup == "/lxc/100/ns/.lxc" and ev.argv[-1] == "requests==2.19.0"
    from ephor import collect
    assert collect.container_of(ev.pid, ev.cgroup) == "lxc:100"
    assert probe.parse_line("D\t4171386\tgetent\t/lxc/100/ns/.lxc\tpypi-org.com").name == "pypi-org.com"
    assert probe.parse_line("C\t4171351\tpip\t/lxc/100/ns/.lxc\t151.101.192.223\t443").port == 443
