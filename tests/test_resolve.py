from ephor import resolve


def _patch_gethostbyaddr(monkeypatch, result=None, error=None):
    calls = []

    def fake(ip):
        calls.append(ip)
        if error is not None:
            raise error
        return result

    monkeypatch.setattr(resolve.socket, "gethostbyaddr", fake)
    resolve._cache.clear()
    return calls


def test_ptr_resolves_and_normalises_hostname(monkeypatch):
    calls = _patch_gethostbyaddr(monkeypatch, result=("Cdn.Example.COM.", [], []))
    assert resolve.ptr("93.184.216.34") == "cdn.example.com"
    assert calls == ["93.184.216.34"]


def test_ptr_falls_back_to_ip_on_failure(monkeypatch):
    _patch_gethostbyaddr(monkeypatch, error=OSError("no PTR record"))
    assert resolve.ptr("203.0.113.5") == "203.0.113.5"


def test_ptr_memoises_lookups(monkeypatch):
    calls = _patch_gethostbyaddr(monkeypatch, result=("cdn.example.com.", [], []))
    assert resolve.ptr("1.2.3.4") == "cdn.example.com"
    assert resolve.ptr("1.2.3.4") == "cdn.example.com"
    assert calls == ["1.2.3.4"]
