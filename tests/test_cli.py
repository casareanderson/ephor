import time

from ephor import cli, store


def test_agents_empty(capsys):
    assert cli.main(["agents"]) == 0
    assert "no agents recorded" in capsys.readouterr().out


def test_agents_json_after_seed(capsys):
    db = store.connect()
    ts = int(time.time())
    with db:
        store.record_agent(db, "ollama", ts)
        store.record_conn(db, "ollama", "registry.ollama.ai", "1.1.1.1", 443, ts, 500000)
    db.close()
    import json
    assert cli.main(["agents", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["agent"] == "ollama"
    assert data[0]["bytes_recv"] == 500000


def test_history_bad_filter(capsys):
    db = store.connect()
    ts = int(time.time())
    with db:
        store.record_conn(db, "a", "good.com", "1.1.1.1", 443, ts, 1)
        store.record_conn(db, "b", "evil.test", "2.2.2.2", 443, ts, 1, bad=True, feed="feodo")
    db.close()
    import json
    assert cli.main(["history", "--bad", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 1 and data[0]["agent"] == "b"


def test_status_json(capsys):
    import json
    assert cli.main(["status", "--json"]) == 0
    st = json.loads(capsys.readouterr().out)
    assert "version" in st and "agents" in st


def test_agent_detail_json(capsys):
    db = store.connect()
    ts = int(time.time())
    with db:
        store.record_conn(db, "scraper", "cdn.example", "1.1.1.1", 443, ts, 999)
    db.close()
    import json
    assert cli.main(["agent", "scraper", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["agent"] == "scraper"
    assert data["destinations"][0]["dest"] == "cdn.example"
