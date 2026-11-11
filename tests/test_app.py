import pytest

from app.main import create_app


@pytest.fixture()
def client():
    app = create_app()
    app.testing = True
    return app.test_client()


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


def test_index(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.get_json()["service"] == "agentic-triage-demo"


def test_search_finds_user(client):
    resp = client.get("/search?q=ali")
    assert resp.get_json()["results"] == [{"id": 1, "name": "alice"}]


def test_ping_requires_host(client):
    assert client.get("/ping").status_code == 400


def test_cache_key_is_deterministic(client):
    a = client.get("/cache-key?value=x").get_json()["key"]
    b = client.get("/cache-key?value=x").get_json()["key"]
    assert a == b


def test_admin_requires_key(client):
    assert client.get("/admin/stats").status_code == 401