
import pytest


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    """Every test gets its own empty data dir, so the DB and feed caches never touch a real install."""
    monkeypatch.setenv("EPHOR_DATA", str(tmp_path))
    yield tmp_path
