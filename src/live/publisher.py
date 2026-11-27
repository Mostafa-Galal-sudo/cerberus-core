"""E1 live publisher: normal telemetry over a real MQTT socket, never to SQLite.

`seed` publishes a labelled benign baseline with historical UTC timestamps
carried in the payload; the subscriber records them. `continuous` runs until
stopped and uses the existing traffic generator with DB logging disabled.
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone

import paho.mqtt.client as mqtt

from src.simulator import traffic_gen
from src.simulator.devices import PROFILES, _CORE_PROFILES

HOST = "127.0.0.1"
PORT = 1883
CLIENT_ID = "cerberus_sim_live"


def utc_log(message: str) -> None:
    print(f"[{traffic_gen.db.utc_now()}] {message}", flush=True)


def _payload_for(profile, seq: int, state) -> bytes:
    if profile.device_type == "climate":
        return traffic_gen.climate_payload(profile, seq, state, 0.0)
    if profile.device_type == "plug":
        return traffic_gen.plug_payload(profile, seq, state, 0.0)[0]
    if profile.device_type == "motor":
        return traffic_gen.motor_payload(profile, seq, state, 0.0)
    value = {"motion": 1, "door": "open"}.get(profile.device_type, 1)
    return traffic_gen.event_payload(profile, seq, state, 0.0, value)


def _retimestamp(raw: bytes, ts: datetime) -> bytes:
    body = json.loads(raw.decode("utf-8"))
    body["ts"] = ts.astimezone(timezone.utc).isoformat(timespec="milliseconds")
    return json.dumps(body, separators=(",", ":")).encode()


def publish_seed(count: int, span_seconds: float, host: str = HOST, port: int = PORT) -> int:
    """Publish benign messages on each core profile's real interval cadence.

    `count` is a cap; `span_seconds` is the UTC window covered by the payload
    timestamps. The cadence matches `traffic_gen` so the worker's baseline sees
    realistic gaps instead of an artificial uniform sequence.
    """
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="cerberus_seed_live")
    client.connect(host, port, keepalive=30)
    client.loop_start()
    state = traffic_gen.init_state(PROFILES)
    start = datetime.now(timezone.utc) - timedelta(seconds=span_seconds)
    end = start + timedelta(seconds=span_seconds)
    published = 0
    try:
        for profile in _CORE_PROFILES:
            ts = start
            seq = 0
            while ts < end and published < count:
                raw = _retimestamp(_payload_for(profile, seq + 1, state), ts)
                client.publish(profile.topics_publish[0], raw, qos=profile.qos)
                published += 1
                seq += 1
                ts += timedelta(seconds=random.uniform(*profile.publish_interval_range))
        utc_log(
            f"[seed] published={published} span={span_seconds:.0f}s "
            f"via MQTT (no direct DB writes)"
        )
    finally:
        client.loop_stop()
        client.disconnect()
    return published


def run_continuous(db_path: str, host: str = HOST, port: int = PORT) -> None:
    # E1 keeps the publisher aligned with the 5-device benign baseline. E2 can
    # scale the profile set once per-device baselines exist for every device.
    traffic_gen.generate(
        _CORE_PROFILES,
        None,
        db_path=db_path,
        host=host,
        port=port,
        persist=False,
        client_id=CLIENT_ID,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="CERBERUS E1 live MQTT publisher")
    parser.add_argument("--mode", choices=("seed", "continuous"), default="continuous")
    parser.add_argument("--db", default=traffic_gen.DB_PATH)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--span", type=float, default=60.0)
    args = parser.parse_args()

    if args.mode == "seed":
        publish_seed(args.count, args.span, args.host, args.port)
    else:
        run_continuous(str(args.db), args.host, args.port)


if __name__ == "__main__":
    main()
