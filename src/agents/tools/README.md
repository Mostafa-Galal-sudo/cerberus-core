# src/agents/tools/

Deterministic evidence-collection tools exposed to the defense agent via
function-calling (Checkpoint 3, task C3-T02).

Planned files:
- `pcap_tools.py` — extract PCAP excerpts around a detection window
- `db_tools.py` — query MQTT event history / incident history from `src/storage`
- `fingerprint_tools.py` — per-device deviation report at detection time

Every tool is read-only toward the environment and writes to the incident
record; every call is audit-logged.
