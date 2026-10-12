import json
import time

from ephor import store, watch


def _alert(**kw) -> watch.Alert:
    base = dict(ts=1, host="box1", container="", agent="scraper", client="curl", crawler=False,
                dest="cdn.example", ip="1.2.3.4", port=443, bytes_recv=0, reason=watch.NEW_DESTINATION)
    base.update(kw)
    return watch.Alert(**base)


# --- client classification -------------------------------------------------

def test_client_binary_curl_and_wget():
    assert watch.client_binary("/usr/bin/curl", "curl https://x") == "curl"
    assert watch.client_binary("/usr/bin/wget", "wget -O f url") == "wget"


def test_client_binary_python_requests():
    assert watch.client_binary("/usr/bin/python3.11", "python3 -m requests.foo") == "python-requests"
    assert watch.client_binary("/usr/bin/python3", "python3 /srv/agent.py") == "python"


def test_client_binary_node():
    assert watch.client_binary("/usr/bin/node", "node /srv/app.js") == "node"


def test_client_binary_crawlers_are_own_type():
    assert watch.client_binary("/usr/bin/chromium", "chromium --headless --remote-debugging") == "crawler:chromium"
    assert watch.client_binary("/usr/bin/node", "node playwright test") == "crawler:playwright"
    assert watch.client_binary("/usr/bin/python3", "scrapy crawl myspider") == "crawler:scrapy"
    assert watch.client_binary("/usr/bin/python3", "python -m crawl4ai") == "crawler:crawl4ai"
    assert watch.is_crawler("crawler:chromium")
    assert not watch.is_crawler("curl")


def test_client_binary_chromium_nonheadless_is_not_crawler():
    assert watch.client_binary("/usr/bin/chromium", "chromium") == "chromium"
    assert not watch.is_crawler("chromium")


# --- destination category --------------------------------------------------

def test_dest_category_crawl_saas():
    assert watch.dest_category("api.firecrawl.dev") == "crawl-saas"
    assert watch.dest_category("scrapingbee.com") == "crawl-saas"
    assert watch.dest_category("cdn.example.com") == ""
    assert watch.dest_category("1.2.3.4") == ""


# --- baseline learning -----------------------------------------------------

def test_baseline_loads_from_history():
    db = store.connect()
    ts = int(time.time())
    with db:
        store.record_conn(db, "ollama", "registry.ollama.ai", "1.1.1.1", 443, ts, 1)
        store.record_conn(db, "ollama", "api.ollama.ai", "2.2.2.2", 11434, ts, 1)
    b = watch.Baseline.load(db)
    assert b.knows_dest("ollama", "registry.ollama.ai")
    assert b.knows_port("ollama", 11434)
    assert not b.knows_dest("ollama", "brand.new.example")
    assert not b.knows_port("ollama", 9999)
    db.close()


def test_baseline_learn():
    b = watch.Baseline()
    b.learn("a", "d", 443)
    assert b.knows_dest("a", "d") and b.knows_port("a", 443)


# --- threshold / anomaly logic --------------------------------------------

def test_known_bad_always_alerts():
    b = watch.Baseline()
    b.learn("a", "evil.test", 443)
    assert watch.analyze(agent="a", dest="evil.test", ip="1.2.3.4", port=443, bytes_recv=10,
                         is_bad=True, indicator="1.2.3.4", feed="feodo",
                         baseline=b, large_transfer_bytes=1048576) == watch.KNOWN_BAD


def test_unusual_port_alerts():
    b = watch.Baseline()
    b.learn("a", "known.example", 443)
    assert watch.analyze(agent="a", dest="known.example", ip="1.2.3.4", port=8080, bytes_recv=10,
                         is_bad=False, indicator="", feed="",
                         baseline=b, large_transfer_bytes=1048576) == watch.UNUSUAL_PORT


def test_new_destination_only_alerts_when_large():
    b = watch.Baseline()
    b.learn("a", "known.example", 443)
    # new host, small transfer -> quiet (threshold gates it)
    assert watch.analyze(agent="a", dest="new.example", ip="9.9.9.9", port=443, bytes_recv=1024,
                         is_bad=False, indicator="", feed="",
                         baseline=b, large_transfer_bytes=1048576) is None
    # new host, large transfer -> alert
    assert watch.analyze(agent="a", dest="new.example", ip="9.9.9.9", port=443, bytes_recv=5_000_000,
                         is_bad=False, indicator="", feed="",
                         baseline=b, large_transfer_bytes=1048576) == watch.NEW_DESTINATION


def test_quiet_known_agent_stays_quiet():
    b = watch.Baseline()
    b.learn("a", "known.example", 443)
    assert watch.analyze(agent="a", dest="known.example", ip="1.2.3.4", port=443, bytes_recv=100_000_000,
                         is_bad=False, indicator="", feed="",
                         baseline=b, large_transfer_bytes=1048576) is None


def test_gate_warmup():
    # known-bad fires even during warm-up; baseline anomalies wait it out
    assert watch.gate(watch.KNOWN_BAD, in_warmup=True)
    assert not watch.gate(watch.NEW_DESTINATION, in_warmup=True)
    assert watch.gate(watch.NEW_DESTINATION, in_warmup=False)
    assert not watch.gate(None, in_warmup=False)


# --- alert sinks -----------------------------------------------------------

def test_stdout_sink(capsys):
    watch.StdoutSink().send(_alert(reason=watch.NEW_DESTINATION, bytes_recv=5_000_000))
    out = capsys.readouterr().out
    assert "NEW_DESTINATION" in out and "scraper" in out and "cdn.example" in out


def test_syslog_sink(monkeypatch):
    sent = []

    class FakeSyslog:
        LOG_WARNING = 4

        def openlog(self, *a):
            pass

        def syslog(self, level, msg):
            sent.append((level, msg))

    monkeypatch.setattr(watch, "syslog", FakeSyslog())
    watch.SyslogSink().send(_alert(reason=watch.UNUSUAL_PORT))
    assert sent and "UNUSUAL_PORT" in sent[0][1]


def test_webhook_sink_generic_json(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=10):
        captured["url"] = req.full_url
        captured["data"] = json.loads(req.data.decode())
        captured["headers"] = req.headers

        class _R:
            def read(self):
                return b""

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return _R()

    monkeypatch.setattr(watch.urllib.request, "urlopen", fake_urlopen)
    watch.WebhookSink("https://example.com/hook").send(_alert(reason=watch.NEW_DESTINATION, bytes_recv=999))
    assert captured["url"] == "https://example.com/hook"
    assert captured["headers"]["Content-type"] == "application/json"
    assert captured["data"]["reason"] == "new_destination"
    assert captured["data"]["host"] == "box1"
    assert captured["data"]["bytes_recv"] == 999


def test_webhook_sink_discord_and_slack_payload():
    a = _alert(reason=watch.KNOWN_BAD, feed="feodo", indicator="1.2.3.4")
    discord = json.loads(watch.WebhookSink("https://discord.com/api/webhooks/x")._payload(a))
    assert "content" in discord and "username" in discord
    slack = json.loads(watch.WebhookSink("https://hooks.slack.com/services/x")._payload(a))
    assert "text" in slack


def test_webhook_sink_fails_soft(monkeypatch):
    def boom(req, timeout=10):
        raise OSError("no network")

    monkeypatch.setattr(watch.urllib.request, "urlopen", boom)
    watch.WebhookSink("https://example.com/hook").send(_alert())  # must not raise


def test_make_sinks():
    sinks = watch.make_sinks(webhook="https://example.com/hook", use_syslog=True)
    kinds = [type(s).__name__ for s in sinks]
    assert kinds == ["StdoutSink", "WebhookSink", "SyslogSink"]


def test_webhook_rejects_non_http_schemes():
    import pytest
    for bad in ("file:///etc/passwd", "ftp://example.com/x", "gopher://x"):
        with pytest.raises(SystemExit):
            watch.make_sinks(bad)
    assert len(watch.make_sinks("https://discord.com/api/webhooks/1/x")) == 2
