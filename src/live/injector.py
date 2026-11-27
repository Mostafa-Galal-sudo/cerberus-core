"""E1 live anomaly injector: policy-bounded attacks published over MQTT only.

The injector owns a DB connection for PolicyGate audit rows, but passes
`conn=None` to the anomaly helpers so telemetry rows are written exclusively by
`src.live.subscriber` from received messages.
"""
from __future__ import annotations

import argparse
import threading
import time

import paho.mqtt.client as mqtt

from src.policy import PolicyGate
from src.simulator import anomalies
from src.storage import db

HOST = "127.0.0.1"
PORT = 1883
SCENARIOS = ("flood", "bloat", "rogue")


def utc_log(message: str) -> None:
    print(f"[{db.utc_now()}] {message}", flush=True)


def run_injector(
    db_path: str,
    *,
    host: str = HOST,
    port: int = PORT,
    interval: float = 20.0,
    count: int = 20,
    scenarios: tuple[str, ...] = SCENARIOS,
    stop_event: threading.Event | None = None,
) -> None:
    conn = db.open_db(db_path)
    gate = PolicyGate(conn=conn)
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="cerberus_injector_live")
    client.connect(host, port, keepalive=30)
    client.loop_start()
    utc_log(f"[injector] ready: scenarios={','.join(scenarios)} interval={interval}s count={count}")

    index = 0
    try:
        while stop_event is None or not stop_event.is_set():
            name = scenarios[index % len(scenarios)]
            action, target, topic = anomalies.SCENARIO_ACTIONS[name]
            attack_id = f"E1-{name}-{index:04d}"
            try:
                decision = gate.require(
                    "attack", action, target,
                    context={"topic": topic, "mode": "live_mqtt", "attack_id": attack_id},
                )
                injected = anomalies.SCENARIOS[name](
                    client, None, decision=decision, count=count, interval=0.0,
                )
                utc_log(
                    f"[injector] attack_id={attack_id} scenario={name} target={target} "
                    f"injected={injected} verdict={'ALLOW' if decision.allowed else 'DENY'}"
                )
            except Exception as exc:
                utc_log(f"[injector] attack_id={attack_id} scenario={name} ERROR={exc}")
            index += 1
            if interval > 0:
                if stop_event is None:
                    time.sleep(interval)
                else:
                    stop_event.wait(interval)
    except KeyboardInterrupt:
        pass
    finally:
        client.loop_stop()
        client.disconnect()
        conn.close()
        utc_log("[injector] stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description="CERBERUS E1 live MQTT anomaly injector")
    parser.add_argument("--db", default=db.DEFAULT_DB_PATH)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--interval", type=float, default=20.0)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--scenarios", default=",".join(SCENARIOS))
    args = parser.parse_args()
    scenarios = tuple(s.strip() for s in args.scenarios.split(",") if s.strip())
    run_injector(
        str(args.db), host=args.host, port=args.port, interval=args.interval,
        count=args.count, scenarios=scenarios or SCENARIOS,
    )


if __name__ == "__main__":
    main()
