from ephor import config, feeds


def _write_cache(name, text):
    (config.data_dir() / f"feed_{name}.txt").write_text(text)


def test_matcher_ip_feed(monkeypatch):
    monkeypatch.setattr(config, "feeds_enabled", lambda: {"feodo": True, "urlhaus": False, "firehol": False, "threatfox": False})
    _write_cache("feodo", "# Feodo\n45.142.212.61\n185.220.101.1\n")
    m = feeds.Matcher()
    bad, ind, feed = m.check(ip="45.142.212.61")
    assert bad and feed == "feodo" and ind == "45.142.212.61"
    assert not m.check(ip="8.8.8.8")[0]


def test_matcher_domain_feed_and_parent(monkeypatch):
    monkeypatch.setattr(config, "feeds_enabled", lambda: {"urlhaus": True, "feodo": False, "firehol": False, "threatfox": False})
    _write_cache("urlhaus", "http://evil.example/malware.bin\nhttps://bad.test:8080/x\n")
    m = feeds.Matcher()
    assert m.check(domain="evil.example")[0]
    assert m.check(domain="sub.evil.example")[0]  # subdomain matches parent
    assert not m.check(domain="good.example")[0]


def test_matcher_firehol_cidr(monkeypatch):
    monkeypatch.setattr(config, "feeds_enabled", lambda: {"firehol": True, "urlhaus": False, "feodo": False, "threatfox": False})
    _write_cache("firehol", "# level1\n203.0.113.0/24\n198.51.100.5\n")
    m = feeds.Matcher()
    bad, ind, feed = m.check(ip="203.0.113.77")
    assert bad and feed == "firehol" and ind == "203.0.113.0/24"
    assert not m.check(ip="203.0.114.1")[0]


def test_matcher_total(monkeypatch):
    monkeypatch.setattr(config, "feeds_enabled", lambda: {"feodo": True, "urlhaus": False, "firehol": False, "threatfox": False})
    _write_cache("feodo", "1.2.3.4\n5.6.7.8\n")
    assert feeds.Matcher().total() == 2


def test_refresh_offline_falls_back_to_cache(monkeypatch):
    monkeypatch.setattr(config, "feeds_enabled", lambda: {"feodo": True, "urlhaus": False, "firehol": False, "threatfox": False})
    _write_cache("feodo", "1.2.3.4\n")

    def boom(url):
        raise OSError("network down")

    monkeypatch.setattr(feeds, "_fetch", boom)
    status = feeds.refresh(force=True)
    assert status["feodo"][0] == "offline"  # kept working against the cache


def test_parsers_tolerate_junk():
    assert feeds._ips("# comment\nnot-an-ip\n9.9.9.9\n") == {"9.9.9.9"}
    assert "evil.test" in feeds._domain_and_ip_from_urlhaus("http://evil.test/a\n#c\n")
