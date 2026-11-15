import pytest
from fastapi.testclient import TestClient

from rerouter.app import create_app
from rerouter.config import Config
from rerouter.db import Database
from rerouter.drivers.simulated import SimulatedRouter


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "t.db")
    yield d
    d.close()


@pytest.fixture
def client(tmp_path):
    cfg = Config(data_dir=tmp_path, admin_password="correct-horse-1", netflow_enabled=False,
                 simulate_traffic=False)
    app = create_app(cfg, driver=SimulatedRouter(seed=1), start_background=False)
    with TestClient(app) as c:
        r = c.post("/api/auth/login", json={"username": "admin", "password": "correct-horse-1"})
        assert r.status_code == 200
        yield c
