"""E1 MQTT subscriber: the only process that writes telemetry rows to SQLite.

Every row comes from a message received over a real MQTT socket. The timestamp
is taken from the simulator's UTC `ts` field when present, otherwise from the
receive time. No publisher or injector writes directly to the DB in live mode.
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import paho.mqtt.client as mqtt

from src.storage import db

HOST = "127.0.0.1"
PORT = 1883
TOPIC = "lab/#"

_TYPE_BY_TOKEN = {
    "climate": "climate",
    "power": "plug",
    "plug_state": "plug",
    "motion": "motion",
    "door": "door",
    "status": "status",
}


def utc_log(message: str) -> None:
    print(f"[{db.utc_now()}] {message}", flush=True)


def _parse_ts(raw: Any) -> str:
    """Return a validated UTC ISO timestamp from a payload, else receive time."""
    if isinstance(raw, str) and raw:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("timestamp has no timezone")
            parsed = parsed.astimezone(timezone.utc)
            now = datetime.now(timezone.utc)
            if now - timedelta(days=1) <= parsed <= now + timedelta(minutes=1):
                return parsed.isoformat(timespec="milliseconds")
        except (ValueError, TypeError):
            pass
    return db.utc_now()


def _type_for_topic(topic: str) -> str:
    for token in topic.split("/"):
        if token in _TYPE_BY_TOKEN:
            return _TYPE_BY_TOKEN[token]
    return "unknown"


def event_from_message(msg: Any) -> dict[str, Any]:
    """Convert one received MQTT message into an `mqtt_events` row."""
    topic = str(msg.topic)
    raw = bytes(msg.payload)
    try:
        body = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeDecodeError):
        body = {}
    if not isinstance(body, dict):
        body = {}

    is_command = topic.endswith("/cmd")
    device_id = "operator" if is_command else str(body.get("device_id") or "unknown")
    device_type = (
        "operator" if is_command
        else str(body.get("device_type") or _type_for_topic(topic))
    )
    return {
        "ts_utc": _parse_ts(body.get("ts")),
        "device_id": device_id,
        "device_type": device_type,
        "topic": topic,
        "qos": int(getattr(msg, "qos", 0) or 0),
        "payload_size": len(raw),
        "payload_preview": raw[:120].decode(errors="replace"),
        "direction": "subscribe" if is_command else "publish",
    }


def build_client(
    db_path: str,
    *,
    topic: str = TOPIC,
    on_saved: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[mqtt.Client, Any]:
    conn = db.open_db(db_path)

    def on_connect(client, userdata, flags, reason_code, properties):
        if getattr(reason_code, "is_failure", False):
            utc_log(f"[subscriber] CONNECT FAILED: {reason_code}")
            return
        client.subscribe(topic, qos=1)
        utc_log(f"[subscriber] subscribing: topic={topic} db={db_path}")

    def on_subscribe(client, userdata, mid, reason_code_list, properties):
        # Ready only after SUBACK: publishing earlier would lose the first messages.
        utc_log(f"[subscriber] ready: topic={topic} db={db_path}")

    def on_message(client, userdata, msg):
        if getattr(msg, "retain", False):
            # Previous runs publish retained status messages; a fresh live DB
            # should only record this run's live telemetry.
            return
        event = event_from_message(msg)
        db.save_event(conn, event)
        if on_saved is not None:
            on_saved(event)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="cerberus_subscriber_live")
    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.user_data_set({"db_path": str(db_path)})
    return client, conn


def run_subscriber(
    db_path: str,
    host: str = HOST,
    port: int = PORT,
    *,
    topic: str = TOPIC,
    stop_event: threading.Event | None = None,
) -> None:
    client, conn = build_client(db_path, topic=topic)
    try:
        client.connect(host, port, keepalive=30)
        client.loop_start()
        while stop_event is None or not stop_event.is_set():
            if stop_event is None:
                time.sleep(0.25)
            else:
                stop_event.wait(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        client.loop_stop()
        client.disconnect()
        conn.close()
        utc_log("[subscriber] stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description="CERBERUS E1 MQTT telemetry subscriber")
    parser.add_argument("--db", default=db.DEFAULT_DB_PATH)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--topic", default=TOPIC)
    args = parser.parse_args()
    run_subscriber(str(args.db), args.host, args.port, topic=args.topic)


if __name__ == "__main__":
    main()
