import os

from ephor import perms


def test_capeff_decode(tmp_path, monkeypatch):
    # CAP_SYS_ADMIN is bit 21 -> 0x200000 ; CAP_NET_RAW is bit 13 -> 0x2000
    status = tmp_path / "status"
    status.write_text("Name:\tx\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapEff:\t0000000000202000\n")
    monkeypatch.setattr(perms, "_status", lambda pid: _parse(status.read_text()))
    caps = perms.capabilities(1)
    assert "sys_admin" in caps
    assert "net_raw" in caps
    assert set(caps) & set(perms._HIGH_RISK)


def test_capeff_zero_is_empty(monkeypatch):
    monkeypatch.setattr(perms, "_status", lambda pid: {"CapEff": "0000000000000000"})
    assert perms.capabilities(1) == []


def test_sudo_unknown_when_not_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert perms.sudo_nopasswd("someuser") == "unknown"


def test_readable_secrets_world_readable(tmp_path, monkeypatch):
    secret = tmp_path / "world.env"
    secret.write_text("TOKEN=x")
    os.chmod(secret, 0o644)  # world-readable
    monkeypatch.setattr(perms, "_status", lambda pid: {"Uid": "1000 1000 1000 1000"})
    hits = perms.readable_secrets(1, [str(secret)])
    assert str(secret) in hits


def test_readable_secrets_root_reads_all(tmp_path, monkeypatch):
    secret = tmp_path / "locked.env"
    secret.write_text("x")
    os.chmod(secret, 0o600)
    monkeypatch.setattr(perms, "_status", lambda pid: {"Uid": "0 0 0 0"})
    assert str(secret) in perms.readable_secrets(1, [str(secret)])


def test_snapshot_shape(monkeypatch):
    monkeypatch.setattr(perms, "_status", lambda pid: {"Uid": "0 0 0 0", "Gid": "0 0 0 0", "CapEff": "0"})
    monkeypatch.setattr(perms, "sudo_nopasswd", lambda u: "unknown")
    snap = perms.snapshot(1, "root", [])
    assert set(snap) == {"identity", "caps", "high_risk_caps", "sudo", "readable_secrets"}


def _parse(text):
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out
