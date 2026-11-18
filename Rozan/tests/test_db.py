"""Tests for the SQLite persistence layer."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.db import ALERT_STATUSES, DEVICE_STATUSES, Database


@pytest.fixture()
def db(tmp_path):
    return Database(tmp_path / "test.db").init()


def _alert(**overrides):
    record = {
        "device_id": "cam-1", "source_label": "Sim-MQTT_Flood",
        "attack_class": "DoS", "is_attack": 1,
        "anomaly_score": 0.97, "rule_score": 1.0, "fused_score": 0.98,
        "confidence": 0.98, "rule_hits": ["flood_rate"], "reasons": ["flood_rate: Rate=200000"],
        "ml_top_features": [["Rate", 0.4]], "explanation": ["[shap] ..."],
        "features": {"Rate": 200000.0},
    }
    record.update(overrides)
    return record


def test_insert_and_get_alert(db):
    alert_id = db.insert_alert(**_alert())
    alert = db.get_alert(alert_id)
    assert alert["rule_hits"] == ["flood_rate"]  # JSON round-trip
    assert alert["status"] == "open"
    assert alert["features"] == {"Rate": 200000.0}
    assert alert["created_at"]


def test_insert_alert_rejects_unknown_fields(db):
    with pytest.raises(ValueError):
        db.insert_alert(bogus_field=1)


def test_list_alerts_filter_status(db):
    db.insert_alert(**_alert())
    db.insert_alert(**_alert(device_id="cam-2"))
    assert len(db.list_alerts()) == 2
    db.set_alert_status(1, "acknowledged")
    assert len(db.list_alerts(status="acknowledged")) == 1
    assert len(db.list_alerts(status="open")) == 1


def test_set_alert_status_validation(db):
    alert_id = db.insert_alert(**_alert())
    assert db.set_alert_status(alert_id, "resolved")
    for bad in ("bogus", None, ""):
        with pytest.raises(ValueError):
            db.set_alert_status(alert_id, bad)
    assert not db.set_alert_status(999, "open")


def test_device_upsert_and_status(db):
    db.upsert_device("cam-1", meta={"type": "camera"})
    db.upsert_device("cam-1")  # update last_seen, keep single row
    devices = db.list_devices()
    assert len(devices) == 1
    assert devices[0]["device_id"] == "cam-1"
    assert db.set_device_status("cam-1", "isolated")
    assert db.list_devices()[0]["status"] == "isolated"
    with pytest.raises(ValueError):
        db.set_device_status("cam-1", "bogus")
    assert not db.set_device_status("ghost", "trusted")


def test_incident_and_timeline(db):
    alert_id = db.insert_alert(**_alert())
    incident_id = db.create_incident("Flood on cam-1", [alert_id])
    assert db.get_incident(incident_id)["alert_ids"] == [alert_id]
    assert db.append_event(incident_id, "detection", "alert created") is not None
    assert db.append_event(incident_id, "response", "device isolated") is not None
    timeline = db.get_timeline(incident_id)
    assert [e["event_type"] for e in timeline] == ["detection", "response"]
    assert db.append_event(999, "x", "y") is None


def test_audit_log(db):
    db.audit("defense_agent", "isolate_device", {"device_id": "cam-1"})
    entries = db.list_audit()
    assert entries[0]["action"] == "isolate_device"
    assert entries[0]["detail"] == {"device_id": "cam-1"}


def test_constants():
    assert set(ALERT_STATUSES) == {"open", "acknowledged", "resolved", "false_positive"}
    assert set(DEVICE_STATUSES) == {"trusted", "suspicious", "isolated"}
