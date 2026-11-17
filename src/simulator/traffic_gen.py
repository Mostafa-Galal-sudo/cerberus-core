import argparse
import json
import random
import secrets
import time

import paho.mqtt.client as mqtt

from src.simulator.devices import PROFILES
from src.storage import db

DB_PATH = "data/lab/lab_traffic.db"
HOST = "localhost"
PORT = 1883
CMD_FILTER = "lab/+/cmd"


def make_payload(profile, seq):
    body = {
        "device_id": profile.device_id,
        "device_type": profile.device_type,
        "seq": seq,
        "ts": db.utc_now(),
        "value": round(random.uniform(18.0, 35.0), 2),
        "rssi": random.randint(-70, -40),
    }
    raw = json.dumps(body, separators=(",", ":")).encode()
    target = random.randint(*profile.payload_size_range)
    if len(raw) < target:
        body["pad"] = secrets.token_hex((target - len(raw)) // 2 + 1)
        raw = json.dumps(body, separators=(",", ":")).encode()
    return raw if len(raw) <= target else raw[:target]


def log_publish(conn, profile, topic, raw, qos):
    db.save_event(conn, {
        "ts_utc": db.utc_now(),
        "device_id": profile.device_id,
        "device_type": profile.device_type,
        "topic": topic,
        "qos": qos,
        "payload_size": len(raw),
        "payload_preview": raw[:120].decode(errors="replace"),
        "direction": "publish",
    })


def log_command(conn, topic, raw):
    db.save_event(conn, {
        "ts_utc": db.utc_now(),
        "device_id": "operator",
        "device_type": "operator",
        "topic": topic,
        "qos": 0,
        "payload_size": len(raw),
        "payload_preview": raw[:120].decode(errors="replace"),
        "direction": "subscribe",
    })


def on_connect(client, userdata, flags, reason_code, properties):
    if getattr(reason_code, "is_failure", False):
        raise ConnectionError(f"MQTT connect failed: {reason_code}")
    print(f"[mqtt] connected ({reason_code})")
    client.subscribe(CMD_FILTER, qos=0)


def on_cmd(client, userdata, msg):
    log_command(userdata["conn"], msg.topic, msg.payload)


def generate(profiles, seconds, db_path=DB_PATH, host=HOST, port=PORT):
    conn = db.open_db(db_path)
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
    client.on_connect = on_connect
    client.on_message = on_cmd
    client.connect(host, port, keepalive=30)
    client.loop_start()

    print(f"[gen] {len(profiles)} devices, {seconds:.0f}s -> {db_path}")
    start = time.monotonic()
    try:
        while time.monotonic() - start < seconds:
            now = time.monotonic()
            for p in profiles:
                if now < next_publish[p.device_id]:
                    continue
                seqs[p.device_id] += 1
                topic = random.choice(p.topics_publish)
                raw = make_payload(p, seqs[p.device_id])
                client.publish(topic, raw, qos=0)
                log_publish(conn, p, topic, raw, qos=0)
                next_publish[p.device_id] = now + random.uniform(
                    *p.publish_interval_range
                )
            time.sleep(0.05)
    finally:
        client.loop_stop()
        client.disconnect()
        stats = db.summarize(conn)
        conn.close()

    print(f"[gen] done: {stats['total_events']} events")
    return stats


def main():
    parser = argparse.ArgumentParser(description="CERBERUS MQTT traffic generator")
    parser.add_argument("--duration", type=float, default=600.0)
    parser.add_argument("--db", default=DB_PATH)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()

    stats = generate(PROFILES, args.duration, db_path=args.db, host=args.host, port=args.port)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
