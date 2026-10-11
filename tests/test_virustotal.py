import time

from ephor import config, virustotal


def test_disabled_without_config(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setitem(config.CONF, "virustotal", {})
    assert virustotal.enabled() is False
    assert virustotal.enabled(flag=True) is False  # flag alone isn't enough without a key


def test_enabled_needs_key_and_optin(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "k")
    monkeypatch.setitem(config.CONF, "virustotal", {})
    assert virustotal.enabled() is False          # key present but not opted in
    assert virustotal.enabled(flag=True) is True  # flag + key
    monkeypatch.setitem(config.CONF, "virustotal", {"enabled": True})
    assert virustotal.enabled() is True            # config opt-in + key


def test_check_destination_malicious(monkeypatch):
    vt = virustotal.VirusTotal(key="k")
    payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 1}}}}
    monkeypatch.setattr(vt, "_get", lambda path: payload)
    res = vt.check_destination(domain="evil.test")
    assert res["malicious"] == 7 and res["source"] == "virustotal"
    # second call is served from cache, not the API
    monkeypatch.setattr(vt, "_get", lambda path: (_ for _ in ()).throw(AssertionError("should be cached")))
    assert vt.check_destination(domain="evil.test")["malicious"] == 7


def test_fail_soft_when_unreachable(monkeypatch):
    vt = virustotal.VirusTotal(key="k")
    monkeypatch.setattr(vt, "_get", lambda path: None)  # simulate VT down / quota / bad key
    assert vt.check_destination(ip="8.8.8.8") is None


def test_rate_limit_skips_when_too_soon(monkeypatch):
    vt = virustotal.VirusTotal(key="k")
    # just "called" -> _ready() should be False, so _get returns None without hitting the network
    vt.state["last"] = time.time()
    called = []
    monkeypatch.setattr(virustotal.urllib.request, "urlopen", lambda *a, **k: called.append(1))
    assert vt._get("/domains/x") is None
    assert not called  # never reached the network


def test_daily_cap(monkeypatch):
    vt = virustotal.VirusTotal(key="k")
    vt.state["count"] = virustotal._DAILY_CAP
    called = []
    monkeypatch.setattr(virustotal.urllib.request, "urlopen", lambda *a, **k: called.append(1))
    assert vt._get("/domains/x") is None
    assert not called


def test_check_hash(monkeypatch):
    vt = virustotal.VirusTotal(key="k")
    payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 40, "suspicious": 0}}}}
    monkeypatch.setattr(vt, "_get", lambda path: payload)
    res = vt.check_hash("a" * 64)
    assert res["malicious"] == 40


def test_budget_report():
    vt = virustotal.VirusTotal(key="k")
    b = vt.budget
    assert b["cap"] == virustotal._DAILY_CAP and b["left"] <= b["cap"]
