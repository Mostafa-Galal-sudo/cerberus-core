"""CERBERUS traffic generator (Checkpoint 1, task C1-T05).

Publishes realistic MQTT traffic for every DeviceProfile and stores each event
in SQLite via src.storage.db. A lightweight subscriber logs inbound command
traffic (direction='subscribe') so the demo shows two-way broker activity.

Run from the repository root:

    python -m src.simulator.traffic_gen --duration 600

Requires a local Mosquitto broker (task C1-T03).
"""

from __future__ import annotations

import argparse
import json
import random
import secrets
import time

import paho.mqtt.client as mqtt

from src.simulator.devices import DEVICE_PROFILES, DeviceProfile
from src.storage import db

DEFAULT_DB = "data/lab/lab_traffic.db"
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 1883
CMD_TOPIC_FILTER = "lab/+/cmd"


def build_payload(profile: DeviceProfile, seq: int) -> bytes:
    """Build a realistic payload sized inside the profile's range.

    The pad field absorbs the size difference so payload_size stats per device
    stay inside the profile's declared range — that is what the fingerprinting
    baseline (Checkpoint 2) will key on.
    """
    base = {
        "device_id": profile.device_id,
        "device_type": profile.device_type,
        "seq": seq,
        "ts": db.utc_now_iso(),
        "value": round(random.uniform(18.0, 35.0), 2),
        "rssi": random.randint(-70, -40),
    }
    raw = json.dumps(base, separators=(",", ":")).encode()
    target = random.randint(*profile.payload_size_range)
    if len(raw) < target:
        pad = secrets.token_hex((target - len(raw)) // 2 + 1)
        base["pad"] = pad
        raw = json.dumps(base, separators=(",", ":")).encode()
    return raw[:target] if len(raw) > target else raw


def store_publish(
    conn, profile: DeviceProfile, topic: str, raw: bytes, qos: int
) -> None:
    db.insert_event(
        conn,
        {
            "ts_utc": db.utc_now_iso(),
            "device_id": profile.device_id,
            "device_type": profile.device_type,
            "topic": topic,
            "qos": qos,
            "payload_size": len(raw),
            "payload_preview": raw[:120].decode(errors="replace"),
            "direction": "publish",
        },
    )


def store_subscribe(conn, topic: str, raw: bytes) -> None:
    db.insert_event(
        conn,
        {
            "ts_utc": db.utc_now_iso(),
            "device_id": "operator",
            "device_type": "operator",
            "topic": topic,
            "qos": 0,
            "payload_size": len(raw),
            "payload_preview": raw[:120].decode(errors="replace"),
            "direction": "subscribe",
        },
    )


def _on_connect(client, userdata, flags, reason_code, properties) -> None:
    if getattr(reason_code, "is_failure", False):
        raise ConnectionError(f"MQTT connect failed: {reason_code}")
    print(f"[mqtt] connected ({reason_code})")
    client.subscribe(CMD_TOPIC_FILTER, qos=0)


def _on_command(client, userdata, msg) -> None:
    conn = userdata["conn"]
    store_subscribe(conn, msg.topic, msg.payload)


def run(
    profiles: tuple[DeviceProfile, ...],
    duration_sec: float,
    db_path: str = DEFAULT_DB,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> dict:
    """Generate traffic for `duration_sec`, then return the DB summary."""
    conn = db.connect(db_path)
    seqs = {p.device_id: 0 for p in profiles}
    next_publish = {
        p.device_id: time.monotonic() + random.uniform(*p.publish_interval_range)
        for p in profiles
    }

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="cerberus_sim",
        userdata={"conn": conn},
    )
    client.on_connect = _on_connect
    client.on_message = _on_command
    client.connect(host, port, keepalive=30)
    client.loop_start()

    print(f"[gen] {len(profiles)} devices, {duration_sec:.0f}s -> {db_path}")
    start = time.monotonic()
    try:
        while time.monotonic() - start < duration_sec:
            now = time.monotonic()
            for p in profiles:
                if now < next_publish[p.device_id]:
                    continue
                seqs[p.device_id] += 1
                topic = random.choice(p.topics_publish)
                raw = build_payload(p, seqs[p.device_id])
                client.publish(topic, raw, qos=0)
                store_publish(conn, p, topic, raw, qos=0)
                next_publish[p.device_id] = now + random.uniform(
                    *p.publish_interval_range
                )
            time.sleep(0.05)
    finally:
        client.loop_stop()
        client.disconnect()
        stats = db.summary(conn)
        conn.close()

    print(f"[gen] done: {stats['total_events']} events")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="CERBERUS MQTT traffic generator")
    parser.add_argument("--duration", type=float, default=600.0, help="seconds to run")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite database path")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    stats = run(DEVICE_PROFILES, args.duration, db_path=args.db, host=args.host, port=args.port)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
