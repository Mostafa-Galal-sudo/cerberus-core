import argparse
import json
import random
import secrets
import time

import paho.mqtt.client as mqtt

from src.simulator import sensors
from src.simulator.devices import PROFILES
from src.storage import db

DB_PATH = "data/lab/lab_traffic.db"
HOST = "localhost"
PORT = 1883
LOOP_DT = 0.05


def init_state(profiles):
    state = {
        "sensors": {},
        "rssi": {},
        "heap": {},
        "uptime": {p.device_id: 0.0 for p in profiles},
        "offline_until": {p.device_id: 0.0 for p in profiles},
        "pending": [],
        "last_state": {p.device_id: None for p in profiles},
    }
    for p in profiles:
        state["rssi"][p.device_id] = sensors.RssiWalk()
        state["heap"][p.device_id] = sensors.HeapWalk()
        if p.device_type == "climate":
            base = 23.5 if p.room == "room1" else 25.5
            state["sensors"][p.device_id] = sensors.ClimateSensor(base, 52.0 if p.room == "room1" else 44.0)
        elif p.device_type == "plug":
            state["sensors"][p.device_id] = sensors.PowerSensor()
    return state


def base_body(profile, seq, state, now):
    return {
        "device_id": profile.device_id,
        "device_type": profile.device_type,
        "room": profile.room,
        "seq": seq,
        "ts": db.utc_now(),
        "uptime": round(state["uptime"][profile.device_id], 1),
        "heap": state["heap"][profile.device_id].step(),
        "rssi": state["rssi"][profile.device_id].step(),
    }


def climate_payload(profile, seq, state, now):
    body = base_body(profile, seq, state, now)
    temp, humid = state["sensors"][profile.device_id].read()
    body["temp"] = temp
    body["humid"] = humid
    return finish(profile, body, now)


def plug_payload(profile, seq, state, now):
    body = base_body(profile, seq, state, now)
    watts, plug_state = state["sensors"][profile.device_id].read()
    body["watts"] = watts
    body["state"] = plug_state
    changed = state["last_state"][profile.device_id] not in (None, plug_state)
    state["last_state"][profile.device_id] = plug_state
    return finish(profile, body, now), changed, plug_state


def event_payload(profile, seq, state, now, value):
    body = base_body(profile, seq, state, now)
    key = "motion" if profile.device_type == "motion" else "door"
    body[key] = value
    return finish(profile, body, now)


def status_payload(profile, state, now, state_name):
    return json.dumps(
        {
            "device_id": profile.device_id,
            "ts": db.utc_now(),
            "state": state_name,
        },
        separators=(",", ":"),
    ).encode()


def finish(profile, body, now):
    raw = json.dumps(body, separators=(",", ":")).encode()
    target = random.randint(*profile.payload_size_range)
    if len(raw) < target:
        body["pad"] = secrets.token_hex((target - len(raw)) // 2 + 1)
        raw = json.dumps(body, separators=(",", ":")).encode()
    return raw if len(raw) <= target else raw[:target]


def log_publish(conn, profile, topic, raw, qos, retain=False):
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
    client.subscribe("lab/+/cmd", qos=1)


def on_cmd(client, userdata, msg):
    conn = userdata["conn"]
    state = userdata["state"]
    log_command(conn, msg.topic, msg.payload)
    try:
        cmd = json.loads(msg.payload)
    except ValueError:
        return
    if cmd.get("action") != "toggle":
        return
    for p in PROFILES:
        if p.device_type == "plug" and p.topic_subscribe[0] == msg.topic:
            state["sensors"][p.device_id].toggle()


def go_offline(client, conn, profile, state, now):
    state["offline_until"][profile.device_id] = now + random.uniform(15.0, 90.0)
    state["uptime"][profile.device_id] = 0.0
    client.publish(profile.status_topic, status_payload(profile, state, now, "offline"), qos=0, retain=True)
    log_publish(conn, profile, profile.status_topic, status_payload(profile, state, now, "offline"), 0)


def come_online(client, conn, profile, state, now):
    client.publish(profile.status_topic, status_payload(profile, state, now, "online"), qos=0, retain=True)
    log_publish(conn, profile, profile.status_topic, status_payload(profile, state, now, "online"), 0)


def publish_event(client, conn, profile, state, seq, now, value, clear_after=None):
    raw = event_payload(profile, seq, state, now, value)
    client.publish(profile.topics_publish[0], raw, qos=profile.qos)
    log_publish(conn, profile, profile.topics_publish[0], raw, profile.qos)
    if clear_after is not None:
        state["pending"].append((now + clear_after, profile, seq, value))


def publish_periodic(client, conn, profile, state, seq, now):
    if profile.device_type == "climate":
        raw = climate_payload(profile, seq, state, now)
        topic = profile.topics_publish[0]
        client.publish(topic, raw, qos=profile.qos)
        log_publish(conn, profile, topic, raw, profile.qos)
    elif profile.device_type == "plug":
        raw, changed, plug_state = plug_payload(profile, seq, state, now)
        topic = profile.topics_publish[0]
        client.publish(topic, raw, qos=profile.qos)
        log_publish(conn, profile, topic, raw, profile.qos)
        if changed:
            state_topic = profile.topics_publish[0].replace("power", "plug_state")
            state_raw = json.dumps({"device_id": profile.device_id, "state": plug_state}, separators=(",", ":")).encode()
            client.publish(state_topic, state_raw, qos=1, retain=True)
            log_publish(conn, profile, state_topic, state_raw, 1)


def handle_pending(client, conn, state, now):
    due = [item for item in state["pending"] if now >= item[0]]
    state["pending"] = [item for item in state["pending"] if now < item[0]]
    for _, profile, seq, value in due:
        clear = {"motion": 0, "door": "closed"}[profile.device_type]
        raw = event_payload(profile, seq, state, now, clear)
        client.publish(profile.topics_publish[0], raw, qos=profile.qos)
        log_publish(conn, profile, profile.topics_publish[0], raw, profile.qos)


def generate(profiles, seconds, db_path=DB_PATH, host=HOST, port=PORT):
    conn = db.open_db(db_path)
    state = init_state(profiles)
    seqs = {p.device_id: 0 for p in profiles}
    next_publish = {
        p.device_id: time.monotonic() + random.uniform(*p.publish_interval_range)
        for p in profiles
    }

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="cerberus_sim",
        userdata={"conn": conn, "state": state},
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
            handle_pending(client, conn, state, now)
            for p in profiles:
                if now < state["offline_until"][p.device_id]:
                    continue
                if random.random() < p.offline_rate_per_hour / 3600 * LOOP_DT:
                    go_offline(client, conn, p, state, now)
                    next_publish[p.device_id] = state["offline_until"][p.device_id] + random.uniform(*p.publish_interval_range)
                    continue
                state["uptime"][p.device_id] += LOOP_DT
                if now < next_publish[p.device_id]:
                    continue
                seqs[p.device_id] += 1
                seq = seqs[p.device_id]
                if p.device_type in ("motion", "door"):
                    first = {"motion": 1, "door": "open"}[p.device_type]
                    clear_after = random.uniform(1.5, 4.0) if p.device_type == "motion" else random.uniform(3.0, 30.0)
                    publish_event(client, conn, p, state, seq, now, first, clear_after)
                else:
                    publish_periodic(client, conn, p, state, seq, now)
                next_publish[p.device_id] = now + random.uniform(*p.publish_interval_range)
            time.sleep(LOOP_DT)
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
