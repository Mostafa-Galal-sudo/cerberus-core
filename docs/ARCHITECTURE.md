# CERBERUS — Architecture

Multi-layer (RF + protocol) intrusion detection, LLM-driven agents, and
policy-bounded automated response on an ESP32-based IoT testbed.

## Five-layer pipeline (proposal Figure 1)

```
+--------------------------------------------------------------+
|  PRESENTATION   SOC dashboard · Telegram/webhook alerts      |
+--------------------------------------------------------------+
                          ^
+--------------------------------------------------------------+
|  RESPONSE       automatic, policy-bounded device isolation   |
+--------------------------------------------------------------+
                          ^
+--------------------------------------------------------------+
|  DEFENSE        LLM agent (Groq): investigates detections,   |
|                 builds incident timeline, decides response   |
+--------------------------------------------------------------+
                          ^
+--------------------------------------------------------------+
|  DETECTION      hybrid engine: ML (Isolation Forest/AE)      |
|                 + rule thresholds + behavioral fingerprinting|
+--------------------------------------------------------------+
                          ^
+--------------------------------------------------------------+
|  ATTACK / TESTBED  LLM attack agent (DeepSeek) + ESP32       |
|                    endpoints, AP, Mosquitto broker, PCAP     |
+--------------------------------------------------------------+
```

Isolation actions feed back into the testbed, changing what the attack layer
sees next (closed loop).

## Data flow — current build (Checkpoint 1)

```
src/simulator/devices.py      DeviceProfile per device class: topics,
        |                     publish-interval range, payload-size range, MAC
        v
src/simulator/traffic_gen.py  jittered MQTT publishes -> local Mosquitto
        |                     + command subscriber logs inbound traffic
        v                         v
   Mosquitto broker      src/storage/db.py -> SQLite (data/lab/)
                             mqtt_events(ts_utc, device_id, topic, qos,
                                         payload_size, ..., direction)
```

Future stages (planned, not built yet):

```
mqtt_events -> src/detection/features.py  -> rules | ML | fingerprint | hybrid
            -> src/agents/ (defense: Groq, attack: DeepSeek)
            -> src/policy/ (single authorization gate, audit log)
            -> src/response/ (isolation) -> src/incidents/ -> src/dashboard/
```

## Invariants

1. **Policy gate.** Privileged actions (attack execution, isolation) route only
   through `src/policy/` — allowlist + scope + rate limit + audit. No bypass path.
2. **Agents propose, policy disposes.** LLM output is never executed directly.
3. **Deterministic fallback.** When LLM APIs fail or are rate-limited, the loop
   degrades to rules-only behavior and must not crash (Checkpoint 3 tests).
4. **UTC everywhere.** Every stored timestamp is ISO8601 UTC so CICIoT2023
   validation and lab data stay comparable.
5. **Profiles mirror firmware.** Simulator device profiles match the ESP32
   firmware behavior so the engine works identically on both.

## Checkpoint status

| Layer | Status |
|-------|--------|
| Testbed / simulator | simulator + anomaly injector running; real ESP32 testbed planned (C4) |
| Detection | done (C2) — rules, Isolation Forest, deviation baseline, device fingerprint, hybrid |
| Agents | done (C3) — Groq defense agent + tools, DeepSeek attack agent, deterministic fallback |
| Response / policy | done (C3) — PolicyGate (allowlist, scope, ratelimit, audit) + simulated isolation |
| Presentation | done (C3) — FastAPI + SSE SOC dashboard (CyFocus dark workspace) |

Task-level plan: `../CERBERUS_WEEKLY_CHECKPOINTS_TASKS.md`.
