import pytest
from fastapi.testclient import TestClient

from rerouter.app import create_app
from rerouter.config import Config
from rerouter.drivers.simulated import SimulatedRouter


@pytest.fixture
def ingest_client(tmp_path):
    cfg = Config(data_dir=tmp_path, admin_password="correct-horse-1", netflow_enabled=False,
                 simulate_traffic=False, ingest_token="secret-ingest-token")
    app = create_app(cfg, driver=SimulatedRouter(seed=1), start_background=False)
    with TestClient(app) as c:
        c.post("/api/auth/login", json={"username": "admin", "password": "correct-horse-1"})
        yield c


def _txn(**over):
    base = dict(client_ip="192.168.1.20", method="GET", scheme="https", host="api.example.com",
                path="/v1/status", status=200, resp_type="application/json", resp_bytes=512,
                duration_ms=42.0)
    base.update(over)
    return base


def test_ingest_requires_token(ingest_client):
    r = ingest_client.post("/api/ingest/http", json={"transactions": [_txn()]})
    assert r.status_code == 401
    r = ingest_client.post("/api/ingest/http", json={"transactions": [_txn()]},
                           headers={"X-Ingest-Token": "wrong"})
    assert r.status_code == 401


def test_ingest_and_query(ingest_client):
    hdr = {"X-Ingest-Token": "secret-ingest-token"}
    body = {"transactions": [_txn(host="a.example.com", path="/one"),
                             _txn(host="b.example.com", path="/two", status=404,
                                  client_ip="192.168.1.21")]}
    r = ingest_client.post("/api/ingest/http", json=body, headers=hdr)
    assert r.status_code == 200 and r.json()["stored"] == 2
    # also accepts a bearer token
    assert ingest_client.post("/api/ingest/http", json={"transactions": [_txn()]},
                              headers={"Authorization": "Bearer secret-ingest-token"}
                              ).status_code == 200

    listing = ingest_client.get("/api/http?range=1h").json()
    assert listing["total"] == 3
    hosts = {r["host"] for r in listing["rows"]}
    assert {"a.example.com", "b.example.com", "api.example.com"} <= hosts

    filtered = ingest_client.get("/api/http?range=1h&host=b.example.com").json()
    assert filtered["total"] == 1 and filtered["rows"][0]["status"] == 404

    top = ingest_client.get("/api/http/top?range=1h&by=host").json()
    assert {r["key"] for r in top} == {"a.example.com", "b.example.com", "api.example.com"}

    status = ingest_client.get("/api/http/status").json()
    assert status["enabled"] is True and status["stored"] == 3 and status["clients"] == 2


def test_ingest_disabled_without_token(client):
    # the default `client` fixture has no ingest_token configured
    r = client.post("/api/ingest/http", json={"transactions": [_txn()]},
                    headers={"X-Ingest-Token": "anything"})
    assert r.status_code == 404
    assert client.get("/api/http/status").json()["enabled"] is False


def test_ingest_validates_payload(ingest_client):
    hdr = {"X-Ingest-Token": "secret-ingest-token"}
    assert ingest_client.post("/api/ingest/http", json={"transactions": []},
                              headers=hdr).status_code == 422
    assert ingest_client.post("/api/ingest/http",
                              json={"transactions": [_txn(status=9999)]},
                              headers=hdr).status_code == 422
