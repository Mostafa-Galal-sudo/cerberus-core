"""End-to-end: detection engine -> SHAP annotation -> SQLite -> REST API."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app import create_app
from backend.ingest import ingest
from detection.engine import HybridDetector
from detection.explain import Explainer, annotate_alerts
from detection.simulator import generate_traffic


@pytest.fixture()
def app_ctx(tmp_path):
    app = create_app(str(tmp_path / "e2e.db"))
    db = app.extensions["cerberus_db"]

    benign = generate_traffic({"mqtt_benign": 200}, seed=21)
    engine = HybridDetector().fit(benign)
    df = generate_traffic({"mqtt_flood": 10, "mqtt_benign": 10}, seed=21)
    df["device_id"] = "cam-1"  # simulator rows share one device
    alerts = engine.score(df)
    annotated = annotate_alerts(df, alerts, Explainer(engine.forest, benign))
    flagged_count = int(alerts["is_alert"].sum())
    ids = ingest(df, annotated, db)
    return app.test_client(), db, ids, flagged_count


def test_pipeline_alerts_reachable_via_api(app_ctx):
    client, _db, ids, flagged_count = app_ctx
    # Persisted alert count must equal the engine's flagged-row count:
    # no unflagged traffic becomes an alert, and no flag is dropped.
    assert len(ids) == flagged_count
    assert 0 < len(ids) < 20
    for alert_id in ids:
        alert = client.get(f"/api/alerts/{alert_id}").get_json()
        assert alert["fused_score"] is not None
        assert alert["features"]["Rate"] > 0
    # At least one flood alert with a real explanation attached.
    flood = [client.get(f"/api/alerts/{i}").get_json() for i in ids]
    with_explanation = [a for a in flood if a["explanation"]]
    assert with_explanation, "expected SHAP-annotated flood alerts"
    assert any("[shap]" in e[0] for e in (a["explanation"] for a in with_explanation))


def test_pipeline_devices_registered(app_ctx):
    client, _db, _ids, _flagged = app_ctx
    devices = client.get("/api/devices").get_json()["devices"]
    assert len(devices) == 1  # flood + benign rows share cam-1
    assert devices[0]["device_id"] == "cam-1"


def test_pipeline_incident_from_alerts(app_ctx):
    client, _db, ids, _flagged = app_ctx
    resp = client.post("/api/incidents", json={"title": "MQTT flood", "alert_ids": ids[:3]})
    incident_id = resp.get_json()["id"]
    events = client.get(f"/api/incidents/{incident_id}/timeline").get_json()["events"]
    assert events[0]["event_type"] == "created"
    audit = client.get("/api/audit").get_json()["entries"]
    assert any(e["action"] == "alerts_persisted" for e in audit)
