"""E1/E2 live anomaly injector: policy-bounded attacks published over MQTT only.

The injector owns a DB connection for PolicyGate audit rows, but passes
`conn=None` to the anomaly helpers so telemetry rows are written exclusively by
`src.live.subscriber` from received messages.

E1 keeps the original single cycling injector. E2 runs dedicated injectors with
distinct MQTT client IDs, lab targets, policy rate-limit buckets, and correlation
IDs carried in both the MQTT payload and the audit context.
"""
from __future__ import annotations

import argparse
import re
import threading
import time
from dataclasses import dataclass

import paho.mqtt.client as mqtt

from src.policy import PolicyGate
from src.simulator import anomalies
from src.storage import db

HOST = "127.0.0.1"
PORT = 1883
SCENARIOS = ("flood", "bloat", "rogue")


@dataclass(frozen=True)
class InjectorSpec:
    injector_id: str
    scenario: str
    target: str
    topic: str


# Five distinct lab targets. Every topic is inside the lab prefix and belongs to
# the target's real simulated profile, so scope checks stay meaningful.
E2_SPECS: tuple[InjectorSpec, ...] = (
    InjectorSpec("e2-inj-1", "flood", "esp32_temp_01", "lab/room1/climate"),
    InjectorSpec("e2-inj-2", "bloat", "esp32_plug_01", "lab/room1/power"),
    InjectorSpec("e2-inj-3", "rogue", "esp32_rogue_99", "lab/room9/unknown"),
    InjectorSpec("e2-inj-4", "flood", "esp32_temp_02", "lab/room2/climate"),
    InjectorSpec("e2-inj-5", "bloat", "esp32_door_01", "lab/garage/door"),
)


def e2_specs(count: int) -> tuple[InjectorSpec, ...]:
    """Return the first `count` E2 specs; the launcher accepts N=3 or N=5."""
    if count < 1 or count > len(E2_SPECS):
        raise ValueError(f"concurrent injector count must be between 1 and {len(E2_SPECS)}")
    return E2_SPECS[:count]


def client_id_for(injector_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", injector_id)
    return f"cerberus_injector_{safe}"


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
    injector_id: str = "e1-primary",
    scenario: str | None = None,
    target: str | None = None,
    topic: str | None = None,
    run_tag: str = "E2",
) -> None:
    dedicated = scenario is not None
    if dedicated and (scenario not in anomalies.SCENARIOS):
        raise ValueError(f"unknown scenario {scenario!r}")

    client_id = client_id_for(injector_id) if dedicated else "cerberus_injector_live"
    scenarios_to_run = (scenario,) if dedicated else scenarios

    conn = db.open_db(db_path)
    gate = PolicyGate(conn=conn)
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    client.connect(host, port, keepalive=30)
    client.loop_start()
    utc_log(
        f"[injector] ready: injector_id={injector_id} client_id={client_id} "
        f"scenarios={','.join(scenarios_to_run)} interval={interval}s count={count}"
    )

    index = 0
    try:
        while stop_event is None or not stop_event.is_set():
            name = scenarios_to_run[index % len(scenarios_to_run)]
            action, default_target, default_topic = anomalies.SCENARIO_ACTIONS[name]
            attack_target = target or default_target
            attack_topic = topic or default_topic

            if dedicated:
                attack_id = f"{run_tag}-{injector_id}-{index:04d}"
            else:
                # Preserve the E1 evidence identifiers exactly.
                attack_id = f"E1-{name}-{index:04d}"

            context = {
                "topic": attack_topic,
                "mode": "live_mqtt",
                "attack_id": attack_id,
                "correlation_id": attack_id,
                "injector_id": injector_id,
            }
            if dedicated:
                # Distinct rate-limit bucket per concurrent injector; audit actor
                # stays 'attack' so the existing allowlist remains authoritative.
                context["rate_key"] = f"injector:{injector_id}"

            try:
                decision = gate.require("attack", action, attack_target, context=context)
                helpers = {
                    "decision": decision,
                    "count": count,
                    "interval": 0.0,
                    "extra": {"correlation_id": attack_id, "injector_id": injector_id},
                }
                if dedicated:
                    # The helper validates the decision against its own device_id,
                    # so the authorized target must be passed through explicitly.
                    helpers["device_id"] = attack_target
                    helpers["topic"] = attack_topic
                injected = anomalies.SCENARIOS[name](client, None, **helpers)
                utc_log(
                    f"[injector] attack_id={attack_id} correlation_id={attack_id} "
                    f"injector_id={injector_id} scenario={name} target={attack_target} "
                    f"injected={injected} verdict={'ALLOW' if decision.allowed else 'DENY'}"
                )
            except Exception as exc:
                utc_log(
                    f"[injector] attack_id={attack_id} correlation_id={attack_id} "
                    f"injector_id={injector_id} scenario={name} ERROR={exc}"
                )
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
        utc_log(f"[injector] stopped injector_id={injector_id}")


def main() -> None:
    parser = argparse.ArgumentParser(description="CERBERUS live MQTT anomaly injector")
    parser.add_argument("--db", default=db.DEFAULT_DB_PATH)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--interval", type=float, default=20.0)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--scenarios", default=",".join(SCENARIOS))
    parser.add_argument("--injector-id", default="e1-primary")
    parser.add_argument("--scenario", choices=tuple(anomalies.SCENARIOS))
    parser.add_argument("--target")
    parser.add_argument("--topic")
    parser.add_argument("--run-tag", default="E2")
    args = parser.parse_args()
    scenarios = tuple(s.strip() for s in args.scenarios.split(",") if s.strip())
    run_injector(
        str(args.db), host=args.host, port=args.port, interval=args.interval,
        count=args.count, scenarios=scenarios or SCENARIOS, injector_id=args.injector_id,
        scenario=args.scenario, target=args.target, topic=args.topic, run_tag=args.run_tag,
    )


if __name__ == "__main__":
    main()
