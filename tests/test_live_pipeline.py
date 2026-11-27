from __future__ import annotations

import json
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import paho.mqtt.client as mqtt
import pytest

from src.live.publisher import publish_seed
from src.live.subscriber import build_client, event_from_message
from src.live.worker import LiveDetectionWorker
from src.storage import db


class _Message:
    def __init__(self, topic: str, payload: bytes, qos: int = 0):
        self.topic = topic
        self.payload = payload
        self.qos = qos


def test_event_from_message_uses_payload_utc_and_maps_command_topic():
    ts = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(timespec="milliseconds")
    body = {"device_id": "esp32_temp_01", "device_type": "climate", "ts": ts, "temp": 22.1}
    event = event_from_message(_Message("lab/room1/climate", json.dumps(body).encode(), 0))
    assert event["ts_utc"] == ts
    assert event["device_id"] == "esp32_temp_01"
    assert event["device_type"] == "climate"
    assert event["direction"] == "publish"

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
    assert "src.live.subscriber" in script
    assert "src.live.publisher" in script
    assert "src.live.worker" in script
    assert "src.live.injector" in script
    assert "src.live.summary" in script
    assert "lp.run(cycles=3, interval=0.5, attack_count=20)" in script
