import json
import sqlite3

import pytest

from src.simulator import sensors
from src.simulator.devices import PROFILES
from src.simulator.traffic_gen import (
    climate_payload,
    event_payload,
    init_state,
    log_command,
    plug_payload,
    status_payload,
)
from src.storage import db


@pytest.fixture
def conn(tmp_path):
    c = db.open_db(tmp_path / "test.db")
    yield c
    c.close()


@pytest.fixture
def state():
    return init_state(PROFILES)


def test_schema_and_indexes_created(tmp_path):
    conn = db.open_db(tmp_path / "test.db")
    tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    indexes = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert "mqtt_events" in tables
    assert {"idx_events_ts", "idx_events_topic", "idx_events_dev"} <= indexes


def test_save_event_roundtrip(conn):
    db.save_event(conn, {
        "ts_utc": "2026-11-17T00:00:00.000+00:00",
        "device_id": "esp32_temp_01",
        "device_type": "climate",
        "topic": "lab/room1/climate",
        "qos": 0,
        "payload_size": 180,
        "payload_preview": '{"device_id":"esp32_temp_01"',
        "direction": "publish",
    })
    row = conn.execute("SELECT * FROM mqtt_events").fetchone()
    assert row["device_id"] == "esp32_temp_01"
    assert row["direction"] == "publish"
    assert row["ts_utc"].endswith("+00:00")


def test_payload_sizes_stay_in_profile_range(state):
    for p in PROFILES:
        sizes = []
        for i in range(50):
            if p.device_type == "climate":
                raw = climate_payload(p, i, state, 0.0)
            elif p.device_type == "plug":
                raw = plug_payload(p, i, state, 0.0)[0]
            else:
                value = {"motion": 1, "door": "open"}[p.device_type]
                raw = event_payload(p, i, state, 0.0, value)
            sizes.append(len(raw))
        lo, hi = p.payload_size_range
        assert min(sizes) >= lo, p.device_id
        assert max(sizes) <= hi, p.device_id


def test_climate_stays_near_baseline(state):
    sensor = sensors.ClimateSensor(23.5, 52.0)
    readings = [sensor.read()[0] for _ in range(200)]
    mean = sum(readings) / len(readings)
    assert abs(mean - 23.5) < 3.0
    assert max(readings) - min(readings) < 6.0


def test_climate_dropout_returns_none_sometimes(state):
    sensor = sensors.ClimateSensor(23.5, 52.0)
    dropouts = sum(1 for _ in range(500) if sensor.read()[1] is None)
    assert 0 < dropouts < 50


def test_power_toggle_changes_state(state):
    plug = state["sensors"]["esp32_plug_01"]
    before = plug.on
    plug.toggle()
    assert plug.on != before


def test_event_payload_values(state):
    motion = next(p for p in PROFILES if p.device_type == "motion")
    door = next(p for p in PROFILES if p.device_type == "door")
    body_motion = json.loads(event_payload(motion, 1, state, 0.0, 1))
    body_door = json.loads(event_payload(door, 1, state, 0.0, "open"))
    assert body_motion["motion"] == 1
    assert body_door["door"] == "open"
    assert body_motion["room"] == "room1"
    assert body_door["room"] == "garage"


def test_status_payload_shape():
    profile = PROFILES[0]
    state = init_state(PROFILES)
    raw = status_payload(profile, state, 0.0, "offline")
    body = json.loads(raw)
    assert body["device_id"] == "esp32_temp_01"
    assert body["state"] == "offline"


def test_summary_aggregates_by_device_and_direction(conn, state):
    for i in range(6):
        raw = climate_payload(PROFILES[0], i, state, 0.0)
        db.save_event(conn, {
            "ts_utc": db.utc_now(),
            "device_id": "esp32_temp_01",
            "device_type": "climate",
            "topic": "lab/room1/climate",
            "qos": 0,
            "payload_size": len(raw),
            "payload_preview": raw[:120].decode(errors="replace"),
            "direction": "publish",
        })
    log_command(conn, "lab/room1/cmd", b'{"action":"toggle"}')
    s = db.summarize(conn)
    assert s["total_events"] == 7
    per_device = {r["device_id"]: r["events"] for r in s["per_device"]}
    assert per_device["esp32_temp_01"] == 6
    directions = {(r["topic"], r["direction"]): r["events"] for r in s["per_topic"]}
    assert directions[("lab/room1/cmd", "subscribe")] == 1


def test_log_command_records_operator(conn):
    log_command(conn, "lab/garage/cmd", b'{"action":"toggle"}')
    row = conn.execute("SELECT * FROM mqtt_events").fetchone()
    assert row["device_id"] == "operator"
    assert row["direction"] == "subscribe"
