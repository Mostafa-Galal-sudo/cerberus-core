"""Tests for the Flask REST API."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app import create_app


@pytest.fixture()
def client(tmp_path):
    app = create_app(str(tmp_path / "api.db"))
    return app.test_client()


def _alert(**overrides):
    record = {
        "device_id": "cam-1", "source_label": "Sim-MQTT_Flood",
        "attack_class": "DoS", "is_attack": 1,
        "anomaly_score": 0.97, "rule_score": 1.0, "fused_score": 0.98,
        "confidence": 0.98, "rule_hits": ["flood_rate"], "reasons": ["r"],
        "features": {"Rate": 200000.0},
    }
    record.update(overrides)
    return record


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_alert_lifecycle(client):
    resp = client.post("/api/alerts", json={"alerts": [_alert(), _alert(device_id="cam-2")]})
    assert resp.status_code == 201
    ids = resp.get_json()["ids"]
    assert ids == [1, 2]

    alert = client.get("/api/alerts/1").get_json()
    assert alert["device_id"] == "cam-1"
    assert alert["rule_hits"] == ["flood_rate"]

    assert client.post("/api/alerts/1/status", json={"status": "acknowledged"}).status_code == 200
    assert client.get("/api/alerts?status=acknowledged").get_json()["alerts"][0]["id"] == 1

    assert client.post("/api/alerts/1/status", json={"status": "nope"}).status_code == 400
    assert client.get("/api/alerts/999").status_code == 404


def test_post_alerts_rejects_malformed(client):
    assert client.post("/api/alerts", json={}).status_code == 400
    assert client.post("/api/alerts", json={"alerts": [42]}).status_code == 400
    bad = _alert()
    bad["bogus"] = 1
    assert client.post("/api/alerts", json={"alerts": [bad]}).status_code == 400


def test_devices(client):
    client.post("/api/alerts", json={"alerts": [_alert()]})
    devices = client.get("/api/devices").get_json()["devices"]
    assert devices[0]["device_id"] == "cam-1"
    resp = client.put("/api/devices/cam-1/status", json={"status": "isolated"})
    assert resp.status_code == 200
    assert client.get("/api/devices").get_json()["devices"][0]["status"] == "isolated"
    assert client.put("/api/devices/cam-1/status", json={"status": "x"}).status_code == 400
    assert client.put("/api/devices/ghost/status", json={"status": "trusted"}).status_code == 404


def test_incidents_and_timeline(client):
    resp = client.post("/api/incidents", json={"title": "Flood", "alert_ids": [1]})
    assert resp.status_code == 201
    incident_id = resp.get_json()["id"]
    events = client.get(f"/api/incidents/{incident_id}/timeline").get_json()["events"]
    assert events[0]["event_type"] == "created"
    assert client.post(
        f"/api/incidents/{incident_id}/events",
        json={"event_type": "response", "message": "isolated cam-1"},
    ).status_code == 201
    timeline = client.get(f"/api/incidents/{incident_id}/timeline").get_json()["events"]
    assert len(timeline) == 2
    assert client.get("/api/incidents/999").status_code == 404
    assert client.post("/api/incidents", json={"title": ""}).status_code == 400


def test_audit_trail(client):
    client.post("/api/alerts", json={"alerts": [_alert()]})
    client.post("/api/alerts/1/status", json={"status": "resolved"})
    entries = client.get("/api/audit").get_json()["entries"]
    actions = [e["action"] for e in entries]
    assert "alerts_ingested" in actions
    assert "alert_status_changed" in actions
