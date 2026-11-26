from __future__ import annotations

import pytest

from src.incidents import IncidentStore
from src.policy import PolicyDeniedError, PolicyGate
from src.storage.db import get_db_path, open_db


def test_extended_schema_tables_created(tmp_path):
    db_path = tmp_path / "test_c3.db"
    conn = open_db(db_path)
    try:
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {"mqtt_events", "policy_audit", "incidents", "incident_events", "isolations"} <= tables
    finally:
        conn.close()


def test_get_db_path_uses_env_and_override(monkeypatch, tmp_path):
    env_db = tmp_path / "env.db"
    override_db = tmp_path / "override.db"
    monkeypatch.setenv("CERBERUS_DB_PATH", str(env_db))

    assert get_db_path() == env_db
    assert get_db_path(override_db) == override_db


def test_incident_opening_requires_policy_allow(tmp_path):
    conn = open_db(tmp_path / "incident_gate.db")
    try:
        gate = PolicyGate(conn=conn)
        store = IncidentStore(conn)
        with pytest.raises(PolicyDeniedError):
            store.create_incident(
                "esp32_temp_01", "high", "det-denied", gate=gate, actor="attack"
            )
        assert store.list_incidents() == []
        assert len(gate.audit.query(verdict="DENY")) == 1
    finally:
        conn.close()


def test_incident_lifecycle_and_ordered_timeline(tmp_path):
    conn = open_db(tmp_path / "incidents.db")
    try:
        store = IncidentStore(conn)
        rec = store.create_incident(
            device_id="esp32_temp_01",
            severity="high",
            detection_ref="det-001",
            initial_evidence={"rate_per_sec": 18.5},
            gate=PolicyGate(conn=conn),
            actor="defense",
        )
        assert rec.status == "open"
        assert len(rec.timeline) == 1
        assert rec.timeline[0].kind == "detection"
        assert rec.timeline[0].details == {"rate_per_sec": 18.5}

        store.append_event(
            rec.id,
            kind="tool_call",
            actor="defense_agent",
            summary="Checked device fingerprint",
            details={"z_score": 9.2},
        )
        updated = store.update_incident(
            rec.id,
            status="mitigated",
            reasoning_summary="Rate flood confirmed",
            decision="isolate_device",
            action="isolate_device",
            outcome="isolated",
        )
        assert updated.status == "mitigated"
        assert updated.decision == "isolate_device"
        assert [e.kind for e in updated.timeline] == ["detection", "tool_call"]

        listed = store.list_incidents(status="mitigated", device_id="esp32_temp_01")
        assert len(listed) == 1
        assert listed[0]["id"] == rec.id
    finally:
        conn.close()
