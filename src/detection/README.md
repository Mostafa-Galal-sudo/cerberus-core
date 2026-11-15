# src/detection/

Hybrid detection engine (Checkpoint 2, tasks C2-T01..T06) — the critical path
of the project.

Planned files:
- `features.py` — feature extraction from raw events/flows (rates, inter-arrival
  stats, payload stats, topic entropy, per-device deviation)
- `dataset.py` — CICIoT2023 loading + label mapping for target attack categories
- `rules_engine.py` — rule-based baseline (threshold rules on publish rate,
  payload size, connection rate)
- `ml_model.py` — Isolation Forest / Autoencoder trained on benign traffic
- `fingerprint.py` — behavioral fingerprinting v1 (per-device baseline + deviation)
- `hybrid.py` — combiner: rule verdict + ML score + fingerprint deviation ->
  calibrated alert with confidence and explanation string

Contract: all three detectors consume the same `features.py` output so the
benchmark (C2-T07) compares methods, not pipelines.
