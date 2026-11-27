from __future__ import annotations

import json
import socket
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import paho.mqtt.client as mqtt
import pytest

from src.live.injector import client_id_for, e2_specs
from src.live.publisher import publish_seed
from src.live.subscriber import build_client, event_from_message
from src.live.worker import LiveDetectionWorker
from src.policy import PolicyGate
from src.policy.ratelimit import RateLimiter
from src.simulator import anomalies
from src.storage import db


class _Message:
    def __init__(self, topic: str, payload: bytes, qos: int = 0):
        self.topic = topic
        self.payload = payload
        self.qos = qos


def test_event_from_message_uses_payload_utc_and_maps_command_topic():
    ts = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(timespec="milliseconds")
    body = {
        "device_id": "esp32_temp_01", "device_type": "climate", "ts": ts, "temp": 22.1,
        "correlation_id": "E2-e2-inj-1-0000", "injector_id": "e2-inj-1",
    }
    event = event_from_message(_Message("lab/room1/climate", json.dumps(body).encode(), 0))
    assert event["ts_utc"] == ts
    assert event["device_id"] == "esp32_temp_01"
    assert event["device_type"] == "climate"
    assert event["direction"] == "publish"
    assert event["correlation_id"] == "E2-e2-inj-1-0000"
    assert event["injector_id"] == "e2-inj-1"

    cmd = event_from_message(_Message("lab/room1/cmd", b'{"action":"toggle"}', 1))
    assert cmd["device_id"] == "operator"
    assert cmd["device_type"] == "operator"
    assert cmd["direction"] == "subscribe"
    assert cmd["qos"] == 1


def _broker_available() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 1883), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not _broker_available(), reason="local Mosquitto broker not available")
def test_subscriber_writes_received_mqtt_message_to_db(tmp_path):
    db_file = tmp_path / "sub.db"
    client, conn = build_client(str(db_file))
    publisher = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="cerberus_test_pub")
    try:
        client.connect("127.0.0.1", 1883, keepalive=30)
        client.loop_start()
        time.sleep(0.4)
        publisher.connect("127.0.0.1", 1883, keepalive=30)
        publisher.loop_start()

        ts = db.utc_now()
        payload = json.dumps(
            {"device_id": "esp32_temp_01", "device_type": "climate", "ts": ts, "temp": 21.5}
        ).encode()
        publisher.publish("lab/room1/climate", payload, qos=1)

        deadline = time.time() + 5.0
        while time.time() < deadline:
            row = conn.execute(
                "SELECT * FROM mqtt_events WHERE device_id = 'esp32_temp_01'"
            ).fetchone()
            if row is not None:
                break
            time.sleep(0.1)
        assert row is not None
        assert row["ts_utc"] == ts
        assert row["topic"] == "lab/room1/climate"
        assert "esp32_temp_01" in row["payload_preview"]
    finally:
        publisher.loop_stop()
        publisher.disconnect()
        client.loop_stop()
        client.disconnect()
        conn.close()


@pytest.mark.skipif(not _broker_available(), reason="local Mosquitto broker not available")
def test_seed_publisher_only_writes_through_subscriber(tmp_path):
    db_file = tmp_path / "seed.db"
    received: list[dict] = []
    client, conn = build_client(str(db_file), on_saved=received.append)
    try:
        client.connect("127.0.0.1", 1883, keepalive=30)
        client.loop_start()
        time.sleep(0.4)
        expected = publish_seed(30, 30.0)
        assert expected > 0
        deadline = time.time() + 5.0
        while time.time() < deadline:
            stored = db.total_events(conn)
            if stored >= expected:
                break
            time.sleep(0.1)
        # Retained lab messages from earlier runs may also arrive; every stored
        # row must still have come through the subscriber callback.
        assert stored >= expected
        assert len(received) == stored
        ts_values = [r[0] for r in conn.execute(
            "SELECT ts_utc FROM mqtt_events ORDER BY id"
        ).fetchall()]
        assert len(set(ts_values)) > 1
    finally:
        client.loop_stop()
        client.disconnect()
        conn.close()


def test_live_worker_creates_incidents_from_real_rules(tmp_path, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    db_file = tmp_path / "worker.db"
    conn = db.open_db(db_file)
    try:
        base = datetime.now(timezone.utc) - timedelta(seconds=120)
        for i in range(240):
            dev = "esp32_temp_01" if i % 2 == 0 else "esp32_plug_01"
            db.save_event(conn, {
                "ts_utc": (base + timedelta(seconds=i / 2)).isoformat(timespec="milliseconds"),
                "device_id": dev,
                "device_type": "climate" if dev.endswith("temp_01") else "plug",
                "topic": "lab/room1/climate" if dev.endswith("temp_01") else "lab/room1/power",
                "qos": 0,
                "payload_size": 180 + (i % 20),
                "payload_preview": '{"benign":true}',
                "direction": "publish",
            })

        worker = LiveDetectionWorker(conn, cooldown=0.0)
        assert worker.fit_baseline() is True

        now = db.utc_now()
        for i in range(20):
            db.save_event(conn, {
                "ts_utc": now,
                "device_id": "esp32_temp_01",
                "device_type": "climate",
                "topic": "lab/room1/climate",
                "qos": 0,
                "payload_size": 210,
                "payload_preview": '{"temp":99.9}',
                "direction": "publish",
            })
        db.save_event(conn, {
            "ts_utc": now,
            "device_id": "esp32_plug_01",
            "device_type": "plug",
            "topic": "lab/room1/power",
            "qos": 0,
            "payload_size": 1200,
            "payload_preview": '{"watts":120.0}',
            "direction": "publish",
        })
        db.save_event(conn, {
            "ts_utc": now,
            "device_id": "esp32_rogue_99",
            "device_type": "unknown",
            "topic": "lab/room9/unknown",
            "qos": 0,
            "payload_size": 400,
            "payload_preview": '{"probe":true}',
            "direction": "publish",
        })

        alerts = worker.poll_once()
        assert alerts >= 3
        devices = {r[0] for r in conn.execute("SELECT device_id FROM incidents").fetchall()}
        assert {"esp32_temp_01", "esp32_plug_01", "esp32_rogue_99"} <= devices
        refs = " ".join(r[0] for r in conn.execute("SELECT detection_ref FROM incidents").fetchall())
        assert "live-" in refs
        assert conn.execute("SELECT COUNT(*) FROM policy_audit").fetchone()[0] > 0
    finally:
        conn.close()


def test_demo_launcher_wires_live_mode_without_removing_c3_default():
    script = (Path(__file__).resolve().parents[1] / "demo.ps1").read_text(encoding="utf-8")
    assert "[switch]$Live" in script
    assert "[int]$StopAfterSeconds" in script
    assert "[int]$ConcurrentInjectors" in script
    assert "--fanout" in script
    assert "--injector-id" in script
    assert "--run-tag" in script
    assert "e2-inj-5" in script
    assert "src.live.subscriber" in script
    assert "src.live.publisher" in script
    assert "src.live.worker" in script
    assert "src.live.injector" in script
    assert "src.live.summary" in script
    assert "lp.run(cycles=3, interval=0.5, attack_count=20)" in script


def test_open_db_migrates_legacy_mqtt_events_with_correlation_columns(tmp_path):
    legacy = tmp_path / "legacy.db"
    old = sqlite3.connect(legacy)
    old.execute(
        "CREATE TABLE mqtt_events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, ts_utc TEXT NOT NULL, "
        "device_id TEXT NOT NULL, device_type TEXT NOT NULL, topic TEXT NOT NULL, "
        "qos INTEGER NOT NULL, payload_size INTEGER NOT NULL, payload_preview TEXT, "
        "direction TEXT NOT NULL)"
    )
    old.commit()
    old.close()

    conn = db.open_db(legacy)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(mqtt_events)")}
        assert {"correlation_id", "injector_id"} <= columns
        db.save_event(conn, {
            "ts_utc": db.utc_now(),
            "device_id": "esp32_temp_01",
            "device_type": "climate",
            "topic": "lab/room1/climate",
            "qos": 0,
            "payload_size": 180,
            "payload_preview": "{}",
            "direction": "publish",
            "correlation_id": "E2-e2-inj-1-0000",
            "injector_id": "e2-inj-1",
        })
        row = conn.execute(
            "SELECT correlation_id, injector_id FROM mqtt_events"
        ).fetchone()
        assert row["correlation_id"] == "E2-e2-inj-1-0000"
        assert row["injector_id"] == "e2-inj-1"
    finally:
        conn.close()


def test_policy_rate_key_context_isolates_concurrent_attackers(tmp_path):
    conn = db.open_db(tmp_path / "policy.db")
    try:
        gate = PolicyGate(conn=conn, ratelimiter=RateLimiter({"attack_flood": (1, 60)}))
        first = gate.authorize(
            "attack", "attack_flood", "esp32_temp_01", {"rate_key": "injector:e2-inj-1"}
        )
        second = gate.authorize(
            "attack", "attack_flood", "esp32_temp_01", {"rate_key": "injector:e2-inj-4"}
        )
        third = gate.authorize(
            "attack", "attack_flood", "esp32_temp_01", {"rate_key": "injector:e2-inj-1"}
        )
        assert first.allowed is True
        assert second.allowed is True
        assert third.allowed is False
        contexts = [
            json.loads(row[0]) for row in conn.execute(
                "SELECT context_json FROM policy_audit ORDER BY id"
            ).fetchall()
        ]
        assert [c["rate_key"] for c in contexts] == [
            "injector:e2-inj-1", "injector:e2-inj-4", "injector:e2-inj-1"
        ]
    finally:
        conn.close()


def test_e2_specs_have_distinct_ids_targets_and_client_ids():
    specs = e2_specs(5)
    assert len(specs) == 5
    assert len({s.injector_id for s in specs}) == 5
    assert len({s.target for s in specs}) == 5
    assert len({client_id_for(s.injector_id) for s in specs}) == 5
    assert all(s.topic.startswith("lab/") for s in specs)
    assert all(s.scenario in ("flood", "bloat", "rogue") for s in specs)
    with pytest.raises(ValueError):
        e2_specs(6)


def test_scenario_helper_uses_authorized_custom_target(tmp_path, monkeypatch):
    conn = db.open_db(tmp_path / "target.db")
    try:
        gate = PolicyGate(conn=conn)
        decision = gate.require(
            "attack", "attack_flood", "esp32_temp_02",
            context={"topic": "lab/room2/climate", "rate_key": "injector:e2-inj-4"},
        )
        captured = []

        def fake_publish(client, db_conn, device_id, device_type, topic, raw, qos=0):
            captured.append((device_id, topic, raw))

        monkeypatch.setattr(anomalies, "_publish", fake_publish)
        injected = anomalies.inject_rate_flood(
            None, None, device_id="esp32_temp_02", topic="lab/room2/climate",
            count=2, decision=decision, extra={"correlation_id": "E2-e2-inj-4-0000"},
        )
        assert injected == 2
        assert len(captured) == 2
        assert all(dev == "esp32_temp_02" and topic == "lab/room2/climate" for dev, topic, _ in captured)
        assert all(b"E2-e2-inj-4-0000" in raw for _, _, raw in captured)
    finally:
        conn.close()


def test_live_worker_fanout_creates_one_incident_per_attack_correlation(tmp_path, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    conn = db.open_db(tmp_path / "fanout.db")
    try:
        base = datetime.now(timezone.utc) - timedelta(seconds=120)
        for i in range(240):
            dev = "esp32_temp_01" if i % 2 == 0 else "esp32_plug_01"
            db.save_event(conn, {
                "ts_utc": (base + timedelta(seconds=i / 2)).isoformat(timespec="milliseconds"),
                "device_id": dev,
                "device_type": "climate" if dev.endswith("temp_01") else "plug",
                "topic": "lab/room1/climate" if dev.endswith("temp_01") else "lab/room1/power",
                "qos": 0,
                "payload_size": 180 + (i % 20),
                "payload_preview": '{"benign":true}',
                "direction": "publish",
            })

        worker = LiveDetectionWorker(conn, fanout=True)
        assert worker.fit_baseline() is True
        now = db.utc_now()
        expected_correlations = {
            "E2-e2-inj-1-0000", "E2-e2-inj-2-0000", "E2-e2-inj-3-0000"
        }
        attack_rows = [
            *[
                ("esp32_temp_01", "climate", "lab/room1/climate", 210, "E2-e2-inj-1-0000", "e2-inj-1")
                for _ in range(20)
            ],
            ("esp32_plug_01", "plug", "lab/room1/power", 1200, "E2-e2-inj-2-0000", "e2-inj-2"),
            ("esp32_rogue_99", "unknown", "lab/room9/unknown", 400, "E2-e2-inj-3-0000", "e2-inj-3"),
        ]
        for dev, dev_type, topic, size, correlation, injector in attack_rows:
            db.save_event(conn, {
                "ts_utc": now,
                "device_id": dev,
                "device_type": dev_type,
                "topic": topic,
                "qos": 0,
                "payload_size": size,
                "payload_preview": '{"attack":true}',
                "direction": "publish",
                "correlation_id": correlation,
                "injector_id": injector,
            })

        alerts = worker.poll_once()
        assert alerts >= 3
        details = [
            json.loads(row[0])
            for row in conn.execute(
                "SELECT details_json FROM incident_events WHERE kind = 'detection'"
            ).fetchall()
        ]
        recorded = set()
        for item in details:
            recorded.update(str(c) for c in item.get("correlation_ids", []))
        assert expected_correlations <= recorded
        refs = [r[0] for r in conn.execute("SELECT detection_ref FROM incidents").fetchall()]
        assert any("live-fanout-" in ref for ref in refs)
    finally:
        conn.close()


def test_fanout_dispatches_each_correlation_once(tmp_path, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    conn = db.open_db(tmp_path / "dedupe.db")
    try:
        base = datetime.now(timezone.utc) - timedelta(seconds=120)
        for i in range(240):
            dev = "esp32_temp_01" if i % 2 == 0 else "esp32_plug_01"
            db.save_event(conn, {
                "ts_utc": (base + timedelta(seconds=i / 2)).isoformat(timespec="milliseconds"),
                "device_id": dev,
                "device_type": "climate" if dev.endswith("temp_01") else "plug",
                "topic": "lab/room1/climate" if dev.endswith("temp_01") else "lab/room1/power",
                "qos": 0,
                "payload_size": 180 + (i % 20),
                "payload_preview": '{"benign":true}',
                "direction": "publish",
            })

        worker = LiveDetectionWorker(conn, fanout=True)
        assert worker.fit_baseline() is True
        correlation = "E2-e2-inj-1-0000"
        for batch in range(2):
            for _ in range(10):
                db.save_event(conn, {
                    "ts_utc": db.utc_now(),
                    "device_id": "esp32_temp_01",
                    "device_type": "climate",
                    "topic": "lab/room1/climate",
                    "qos": 0,
                    "payload_size": 210,
                    "payload_preview": '{"attack":true}',
                    "direction": "publish",
                    "correlation_id": correlation,
                    "injector_id": "e2-inj-1",
                })
            assert worker.poll_once() == (1 if batch == 0 else 0)

        refs = [
            r[0] for r in conn.execute(
                "SELECT detection_ref FROM incidents WHERE detection_ref LIKE 'live-fanout-%'"
            ).fetchall()
        ]
        assert len(refs) == 1
    finally:
        conn.close()
