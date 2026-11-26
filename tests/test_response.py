from __future__ import annotations

import pytest

from src.incidents import IncidentStore
from src.policy import PolicyDeniedError, PolicyGate
from src.response import IsolationRegistry, isolate_device, release_device
from src.storage.db import open_db


def test_isolate_and_release_require_policy_and_update_incident(tmp_path):
    conn = open_db(tmp_path / "resp.db")
    try:
        gate = PolicyGate(conn=conn)
        incidents = IncidentStore(conn)
        inc = incidents.create_incident(
            "esp32_temp_01", "high", "det-42", gate=gate, actor="defense"
        )

        # Attack actor must be denied
        denied = isolate_device(
            conn,
            gate,
            "esp32_temp_01",
            actor="attack",
            incident_id=inc.id,
            incidents=incidents,
        )
        assert denied.executed is False
        assert denied.decision.allowed is False

        # Defense actor is allowed
        res = isolate_device(
            conn,
            gate,
            "esp32_temp_01",
            actor="defense",
            reason="MQTT flood",
            ttl_sec=120,
            incident_id=inc.id,
            incidents=incidents,
        )
        assert res.executed is True
        assert res.record is not None
        assert res.record.status == "active"

        reg = IsolationRegistry(conn)
        assert reg.is_isolated("esp32_temp_01") is True

        rel = release_device(
            conn,
            gate,
            "esp32_temp_01",
            actor="operator",
            incident_id=inc.id,
            incidents=incidents,
        )
        assert rel.executed is True
        assert reg.is_isolated("esp32_temp_01") is False

        rec = incidents.get_record(inc.id)
        assert rec is not None
        assert rec.status == "resolved"
        assert [e.kind for e in rec.timeline] == [
            "detection",
            "policy_denied",
            "isolation",
            "release",
        ]
    finally:
        conn.close()


def test_registry_rejects_execution_without_allow_decision(tmp_path):
    conn = open_db(tmp_path / "registry_gate.db")
    try:
        gate = PolicyGate(conn=conn)
        denied = gate.authorize("attack", "isolate_device", "esp32_temp_01")
        reg = IsolationRegistry(conn)
        with pytest.raises(PolicyDeniedError):
            reg.activate(
                "esp32_temp_01",
                decision=denied,
                reason="bypass attempt",
                actor="attack",
            )
        with pytest.raises(PolicyDeniedError):
            reg.release("esp32_temp_01", decision=denied)
        assert reg.list_isolations() == []
    finally:
        conn.close()


def test_isolation_expiry_steps_down_stale_records(tmp_path):
    conn = open_db(tmp_path / "expiry.db")
    try:
        gate = PolicyGate(conn=conn)
        isolate_device(conn, gate, "esp32_plug_01", actor="defense", ttl_sec=0)
        reg = IsolationRegistry(conn)
        assert reg.is_isolated("esp32_plug_01") is False
        rows = reg.list_isolations(device_id="esp32_plug_01")
        assert rows[0]["status"] == "expired"
    finally:
        conn.close()
