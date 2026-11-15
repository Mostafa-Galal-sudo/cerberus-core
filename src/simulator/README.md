# src/simulator/

Simulated IoT traffic generation (Checkpoint 1, tasks C1-T04..T07). Produces the
behavioral baseline the whole detection engine trains on before real hardware
exists.

Planned files:
- `devices.py` — `DeviceProfile` dataclasses: topics, publish-interval ranges,
  payload-size ranges, MAC per device type
- `traffic_gen.py` — main generator: publishes jittered MQTT traffic per profile,
  stores every event via `src/storage`
- `anomalies.py` — later: injects synthetic anomalies for detector sanity tests (C2-T09)

Design note: per-device differences in interval and payload size are the
behavioral fingerprint signal — do not homogenize profiles.
