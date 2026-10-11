import time

from ephor import store


def test_record_and_aggregate():
    db = store.connect()
    ts = int(time.time())
    with db:
        store.record_agent(db, "hermes:coder", ts)
        store.record_conn(db, "hermes:coder", "example.com", "93.184.216.34", 443, ts, 1000)
        store.record_conn(db, "hermes:coder", "example.com", "93.184.216.34", 443, ts + 1, 50000)
        store.record_conn(db, "hermes:coder", "evil.test", "1.2.3.4", 443, ts, 20, bad=True, feed="feodo")
        store.record_alert(db, "hermes:coder", "evil.test", "1.2.3.4", "feodo", "1.2.3.4", ts)
    rows = {r["agent"]: r for r in store.agents(db)}
    a = rows["hermes:coder"]
    assert a["dests"] == 2
    assert a["bad_dests"] == 1
    assert a["bytes_recv"] == 50020  # max per dest (50000) + 20
    db.close()


def test_bytes_recv_keeps_max_not_sum():
    db = store.connect()
    ts = int(time.time())
    with db:
        store.record_conn(db, "a", "d", "1.1.1.1", 443, ts, 100)
        store.record_conn(db, "a", "d", "1.1.1.1", 443, ts + 1, 80)  # smaller — ignored
    row = store.agent_conns(db, "a")[0]
    assert row["bytes_recv"] == 100
    assert row["times_seen"] == 2
    db.close()


def test_history_filters():
    db = store.connect()
    ts = int(time.time())
    with db:
        store.record_conn(db, "a", "good", "1.1.1.1", 443, ts, 1)
        store.record_conn(db, "b", "bad", "2.2.2.2", 443, ts, 1, bad=True, feed="urlhaus")
    assert len(store.history(db)) == 2
    assert len(store.history(db, bad_only=True)) == 1
    assert len(store.history(db, agent="a")) == 1
    assert store.history(db, bad_only=True)[0]["agent"] == "b"
    db.close()


def test_stats():
    db = store.connect()
    ts = int(time.time())
    with db:
        store.record_agent(db, "a", ts)
        store.record_conn(db, "a", "d", "1.1.1.1", 443, ts, 1, bad=True, feed="feodo")
        store.record_alert(db, "a", "d", "1.1.1.1", "feodo", "1.1.1.1", ts)
    st = store.stats(db)
    assert st["agents"] == 1 and st["bad_destinations"] == 1 and st["alerts"] == 1
    db.close()
