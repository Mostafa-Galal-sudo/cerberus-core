from __future__ import annotations

from fastapi.testclient import TestClient

from src.dashboard import create_app
from src.incidents import IncidentStore
from src.policy import PolicyGate
from src.response import isolate_device
from src.storage.db import open_db, save_event


def test_dashboard_endpoints_and_release_flow(tmp_path, monkeypatch):
    db_file = tmp_path / "dash.db"
    conn = open_db(db_file)
    try:
        save_event(
            conn,
            {
                "ts_utc": "2026-11-26T10:00:00.000+00:00",
                "device_id": "esp32_temp_01",
                "device_type": "climate",
                "topic": "lab/room1/climate",
                "qos": 0,
                "payload_size": 180,
                "payload_preview": '{"temp": 22.0}',
                "direction": "publish",
            },
        )
        gate = PolicyGate(conn=conn)
        incidents = IncidentStore(conn)
        inc = incidents.create_incident(
            "esp32_temp_01", "high", "det-dash-1", gate=gate, actor="defense"
        )
        isolate_device(
            conn,
            gate,
            "esp32_temp_01",
            actor="defense",
            reason="flood test",
            incident_id=inc.id,
            incidents=incidents,
        )
    finally:
        conn.close()

    monkeypatch.setenv("CERBERUS_DASHBOARD_TOKEN", "test-release-token")
    app = create_app(db_path=db_file)
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        health = client.get("/api/health").json()
        assert health["status"] == "ok"
        assert health["active_isolations"] == 1

        ov = client.get("/api/overview").json()
        assert ov["kpis"]["total_events"] == 1
        temp_dev = next(d for d in ov["devices"] if d["device_id"] == "esp32_temp_01")
        assert temp_dev["status"] == "isolated"

        detail = client.get(f"/api/incidents/{inc.id}").json()
        assert len(detail["timeline"]) >= 2

        url = f"/api/isolations/esp32_temp_01/release?incident_id={inc.id}"
        assert client.post(url).status_code == 401
        assert client.post(url, headers={"X-Cerberus-Token": "wrong"}).status_code == 401

        rel = client.post(url, headers={"X-Cerberus-Token": "test-release-token"})
        assert rel.status_code == 200
        assert rel.json()["released"] is True

        audit = client.get("/api/audit").json()
        assert audit["count"] >= 2

        sse = client.get("/api/stream?once=true")
        assert sse.status_code == 200
        assert "data:" in sse.text
        assert '"audit"' in sse.text


def test_dashboard_release_fails_closed_without_configured_token(tmp_path, monkeypatch):
    monkeypatch.delenv("CERBERUS_DASHBOARD_TOKEN", raising=False)
    app = create_app(db_path=tmp_path / "noauth.db")
    with TestClient(app) as client:
        res = client.post("/api/isolations/esp32_temp_01/release")
        assert res.status_code == 503
        assert res.json()["detail"] == "DASHBOARD_AUTH_NOT_CONFIGURED"
