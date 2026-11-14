def test_auth_required(client):
    client.cookies.clear()
    assert client.get("/api/status").status_code == 401
    assert client.post("/api/auth/login", json={"username": "admin",
                                                "password": "wrong"}).status_code == 401


def test_status_and_interfaces(client):
    s = client.get("/api/status").json()
    assert s["driver"] == "simulated" and "firewall" in s["capabilities"]
    names = [i["name"] for i in client.get("/api/interfaces").json()]
    assert "wan" in names


def test_firewall_crud_is_audited(client):
    r = client.post("/api/firewall/rules", json={"name": "block-telnet", "action": "drop",
                                                 "proto": "tcp", "dst_port": "23"})
    assert r.status_code == 200, r.text
    rid = r.json()["id"]
    assert any(x["id"] == rid for x in client.get("/api/firewall/rules").json())
    assert client.delete(f"/api/firewall/rules/{rid}").status_code == 200
    actions = [a["action"] for a in client.get("/api/audit").json()]
    assert "firewall_rule_add" in actions and "firewall_rule_delete" in actions


def test_validation_rejects_injection(client):
    r = client.post("/api/firewall/rules", json={"name": "x", "src": "1.2.3.4; reboot"})
    assert r.status_code == 422
    r = client.post("/api/diagnostics/ping", json={"host": "8.8.8.8 && reboot"})
    assert r.status_code == 422


def test_block_device(client):
    mac = "24:0a:c4:a1:77:07"
    assert client.post(f"/api/devices/{mac}/block", json={"blocked": True}).status_code == 200
    rules = client.get("/api/firewall/rules").json()
    assert any(r["src_mac"] == mac and r["managed"] for r in rules)
    client.post(f"/api/devices/{mac}/block", json={"blocked": False})
    assert not any(r["src_mac"] == mac for r in client.get("/api/firewall/rules").json())


def test_settings_roundtrip(client):
    s = client.get("/api/settings").json()["runtime"]
    s["lan_networks"] = ["192.168.1.0/24"]
    s["alerts"]["scan_targets"] = 25
    assert client.put("/api/settings", json=s).status_code == 200
    assert client.get("/api/settings").json()["runtime"]["alerts"]["scan_targets"] == 25
    s["lan_networks"] = ["not-a-network"]
    assert client.put("/api/settings", json=s).status_code == 422


def test_traffic_endpoints_empty_db(client):
    for path in ("summary", "timeseries", "top", "sankey", "graph", "heatmap", "distribution",
                 "flows"):
        assert client.get(f"/api/traffic/{path}?range=1h").status_code == 200, path
    assert client.get("/api/traffic/timeseries?group_by=evil").status_code == 422
    r = client.get("/api/traffic/export?range=1h&format=csv")
    assert r.status_code == 200 and r.text.startswith("id,ts_start")


def test_wifi_key_not_audited(client):
    r = client.patch("/api/wifi/default_radio0", json={"key": "brand-new-key"})
    assert r.status_code == 200
    entry = client.get("/api/audit").json()[0]
    assert entry["details"]["key"] == "********"


def test_live_websocket(client):
    with client.websocket_connect("/api/live") as ws:
        hello = ws.receive_json()
        assert hello["topic"] == "hello" and "status" in hello["data"]


def test_live_websocket_requires_auth(client):
    import pytest
    from starlette.websockets import WebSocketDisconnect

    client.cookies.clear()
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/live") as ws:
            ws.receive_json()
