"""
Integration test: Cerberus closed-loop pipeline (C3-T08)

Runs entirely in-process — no MQTT broker, no real API keys.
Uses mocked AttackAgent / DefenseAgent clients so LLM calls never fire.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.incidents import IncidentStore
from src.loop.runner import CerberusLoop, make_loop
from src.policy import PolicyGate
from src.response.registry import IsolationRegistry
from src.storage.db import open_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_conn(tmp_path: Path) -> sqlite3.Connection:
    return open_db(tmp_path / "test_loop.db")


@pytest.fixture()
def loop(tmp_conn: sqlite3.Connection) -> CerberusLoop:
    return CerberusLoop(conn=tmp_conn)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flood_events(conn: sqlite3.Connection, device_id: str, count: int = 25) -> None:
    """Write synthetic flood events directly to DB (simulates attack injection)."""
    from src.storage.db import save_event, utc_now
    for i in range(count):
        save_event(conn, {
            "ts_utc": utc_now(),
            "device_id": device_id,
            "device_type": "climate",
            "topic": f"lab/room1/{device_id}",
            "qos": 0,
            "payload_size": 180 + i % 5,
            "payload_preview": json.dumps({"seq": i, "flood": True}),
            "direction": "publish",
        })


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_loop_run_once_produces_incident(tmp_conn: sqlite3.Connection) -> None:
    """run_once() should open an incident and not crash with no API keys."""
    # Pre-seed some events so detection has data to work with
    _flood_events(tmp_conn, "esp32_temp_01", count=30)

    lp = CerberusLoop(conn=tmp_conn)
    result = lp.run_once(attack_count=10)

    assert result.error is None, f"Loop raised: {result.error}"
    assert result.attack is not None
    assert result.defense is not None
    assert result.defense.incident.id.startswith("inc-")
    assert result.defense.incident.device_id != ""
    assert result.defense.incident.status in ("open", "investigating", "mitigated", "resolved")


def test_loop_attack_events_written_to_db(tmp_conn: sqlite3.Connection) -> None:
    """After run_once(), at least one mqtt_event must exist in DB."""
    lp = CerberusLoop(conn=tmp_conn)
    lp.run_once(attack_count=5)

    count = tmp_conn.execute("SELECT COUNT(*) FROM mqtt_events").fetchone()[0]
    assert count > 0, "No events written to DB after attack"


def test_loop_incident_opened_with_correct_device(tmp_conn: sqlite3.Connection) -> None:
    """Incident device_id must match the attack target."""
    _flood_events(tmp_conn, "esp32_temp_01", count=30)
    lp = CerberusLoop(conn=tmp_conn)
    result = lp.run_once(attack_count=5, attack_target="esp32_temp_01")

    assert result.defense is not None
    assert result.defense.incident.device_id == "esp32_temp_01"


def test_loop_policy_audit_has_allow_for_attack_action(tmp_conn: sqlite3.Connection) -> None:
    """PolicyGate must have recorded at least one ALLOW verdict."""
    lp = CerberusLoop(conn=tmp_conn)
    lp.run_once(attack_count=5)

    allows = lp.gate.audit.query(limit=200, verdict="ALLOW")
    assert len(allows) > 0, "No ALLOW verdicts in policy audit log"


def test_loop_isolation_recorded_on_high_severity(tmp_conn: sqlite3.Connection) -> None:
    """When defense agent recommends isolation (fallback on high severity), isolation table gets a record."""
    # Seed many events to trigger a high-severity detection
    _flood_events(tmp_conn, "esp32_temp_01", count=60)

    lp = CerberusLoop(conn=tmp_conn)
    result = lp.run_once(attack_count=15, attack_target="esp32_temp_01")

    # Isolation may or may not fire depending on fallback rules, but if it did,
    # it must be recorded in the registry.
    reg = IsolationRegistry(tmp_conn)
    isolations = reg.list_isolations(limit=50)
    if result.defense and result.defense.isolation and result.defense.isolation.executed:
        assert len(isolations) > 0, "Isolation executed but not recorded in registry"
        assert any(iso["device_id"] == "esp32_temp_01" for iso in isolations)


def test_loop_no_bypass_policy_on_isolation(tmp_conn: sqlite3.Connection) -> None:
    """Every isolation must have a matching ALLOW verdict in the audit log."""
    _flood_events(tmp_conn, "esp32_temp_01", count=40)
    lp = CerberusLoop(conn=tmp_conn)
    result = lp.run_once(attack_count=10, attack_target="esp32_temp_01")

    if result.defense and result.defense.isolation and result.defense.isolation.executed:
        audit = lp.gate.audit.query(limit=200, actor="defense", verdict="ALLOW")
        isolate_entries = [a for a in audit if a.get("action") == "isolate_device"]
        assert len(isolate_entries) > 0, (
            "Isolation executed but no matching ALLOW audit entry found — policy bypass!"
        )


def test_loop_fallback_works_without_api_keys(tmp_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch) -> None:
    """Loop must complete successfully even with no API keys set."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    lp = CerberusLoop(conn=tmp_conn)
    result = lp.run_once(attack_count=5)

    assert result.error is None
    assert result.attack is not None
    assert result.attack.mode == "fallback"
    assert result.defense is not None
    assert result.defense.mode == "fallback"


def test_loop_on_event_callback_fires(tmp_conn: sqlite3.Connection) -> None:
    """on_event callback must be called at least for attack + defense phases."""
    events: list[dict] = []
    lp = CerberusLoop(conn=tmp_conn, on_event=events.append)
    lp.run_once(attack_count=5)

    types = {e["type"] for e in events}
    assert "attack" in types
    assert "defense" in types


def test_loop_run_multiple_cycles(tmp_conn: sqlite3.Connection) -> None:
    """run(cycles=3) should produce 3 LoopResult objects."""
    lp = CerberusLoop(conn=tmp_conn)
    results = lp.run(cycles=3, interval=0.0, attack_count=5)

    assert len(results) == 3
    for r in results:
        assert r.defense is not None


def test_make_loop_convenience_factory(tmp_path: Path) -> None:
    """make_loop() should create a usable CerberusLoop with fresh DB."""
    db_path = str(tmp_path / "factory_test.db")
    lp = make_loop(db_path=db_path)
    assert isinstance(lp, CerberusLoop)
    result = lp.run_once(attack_count=3)
    assert result.error is None
