import argparse
import json
import secrets
import time

import paho.mqtt.client as mqtt

from src.policy import PolicyDecision, PolicyDeniedError, PolicyGate
from src.storage import db

DB_PATH = "data/lab/lab_traffic.db"
HOST = "localhost"
PORT = 1883


def _build_payload(device_id, device_type, payload_size, seq, extra=None):
    body = {
        "device_id": device_id,
        "device_type": device_type,
        "seq": seq,
        "ts": db.utc_now(),
    }
    if extra:
        body.update(extra)
    raw = json.dumps(body, separators=(",", ":")).encode()
    needed = payload_size - len(raw)
    if needed >= 9:
        body["pad"] = secrets.token_hex((needed - 9) // 2) + ("a" if (needed - 9) % 2 else "")
        raw = json.dumps(body, separators=(",", ":")).encode()
    return raw


def _publish(client, conn, device_id, device_type, topic, raw, qos=0):
    if client is not None:
        client.publish(topic, raw, qos=qos)
    if conn is not None:
        db.save_event(conn, {
            "ts_utc": db.utc_now(),
            "device_id": device_id,
            "device_type": device_type,
            "topic": topic,
            "qos": qos,
            "payload_size": len(raw),
            "payload_preview": raw[:120].decode(errors="replace"),
            "direction": "publish",
        })


def require_decision(decision: PolicyDecision | None, action: str, target: str) -> None:
    if decision is None or not decision.allowed:
        raise PolicyDeniedError(f"no ALLOW decision for {action} on {target!r}")
    if decision.action != action or decision.target != target:
        raise PolicyDeniedError(
            f"decision mismatch: expected {action} on {target!r}, "
            f"got {decision.action} on {decision.target!r}"
        )


def inject_rate_flood(
    client,
    conn,
    device_id="esp32_temp_01",
    topic="lab/room1/climate",
    count=150,
    interval=0.05,
    payload_size=200,
    *,
    decision: PolicyDecision,
):
    require_decision(decision, "attack_flood", device_id)
    for seq in range(1, count + 1):
        raw = _build_payload(device_id, "climate", payload_size, seq, {"temp": 99.9})
        _publish(client, conn, device_id, "climate", topic, raw, qos=0)
        if interval > 0:
            time.sleep(interval)
    return count


def inject_payload_bloat(
    client,
    conn,
    device_id="esp32_plug_01",
    topic="lab/room1/power",
    count=6,
    interval=0.5,
    payload_size=1200,
    *,
    decision: PolicyDecision,
):
    require_decision(decision, "attack_bloat", device_id)
    for seq in range(1, count + 1):
        raw = _build_payload(device_id, "plug", payload_size, seq, {"watts": 120.0, "state": "on"})
        _publish(client, conn, device_id, "plug", topic, raw, qos=0)
        if interval > 0:
            time.sleep(interval)
    return count


def inject_rogue_device(
    client,
    conn,
    device_id="esp32_rogue_99",
    topic="lab/room9/unknown",
    count=10,
    interval=0.2,
    payload_size=400,
    *,
    decision: PolicyDecision,
):
    require_decision(decision, "attack_rogue", device_id)
    for seq in range(1, count + 1):
        raw = _build_payload(device_id, "unknown", payload_size, seq, {"probe": True})
        _publish(client, conn, device_id, "unknown", topic, raw, qos=0)
        if interval > 0:
            time.sleep(interval)
    return count


SCENARIOS = {
    "flood": inject_rate_flood,
    "bloat": inject_payload_bloat,
    "rogue": inject_rogue_device,
}

SCENARIO_ACTIONS = {
    "flood": ("attack_flood", "esp32_temp_01", "lab/room1/climate"),
    "bloat": ("attack_bloat", "esp32_plug_01", "lab/room1/power"),
    "rogue": ("attack_rogue", "esp32_rogue_99", "lab/room9/unknown"),
}


def inject_all(db_path=DB_PATH, host=HOST, port=PORT, scenarios=("flood", "bloat", "rogue"), gate=None):
    conn = db.open_db(db_path)
    gate = gate or PolicyGate(conn=conn)
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="cerberus_anomaly_inj")
    client.connect(host, port, keepalive=30)
    client.loop_start()
    counts = {}
    try:
        for name in scenarios:
            action, target, topic = SCENARIO_ACTIONS[name]
            decision = gate.require("attack", action, target, context={"topic": topic, "mode": "cli"})
            counts[name] = SCENARIOS[name](client, conn, decision=decision)
    finally:
        client.loop_stop()
        client.disconnect()
        conn.close()
    return counts


def main():
    parser = argparse.ArgumentParser(description="CERBERUS live MQTT anomaly injector")
    parser.add_argument("--scenario", choices=["all", *SCENARIOS.keys()], default="all")
    parser.add_argument("--db", default=DB_PATH)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()

    selected = tuple(SCENARIOS.keys()) if args.scenario == "all" else (args.scenario,)
    counts = inject_all(db_path=args.db, host=args.host, port=args.port, scenarios=selected)
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    main()
