# PROGRESS — weekly log

One entry per checkpoint: what shipped, evidence, what slipped.
The task-level plan lives in `../CERBERUS_WEEKLY_CHECKPOINTS_TASKS.md`.

## Checkpoint 1 — Foundation & Data Pipeline (16–22 Nov) — ✅ COMPLETE 17 Nov

| Task | Result | Evidence |
|------|--------|----------|
| C1-T01 repo scaffold | structure + `.gitignore` (data/, secrets excluded) | commit `499d151` |
| C1-T02 README + ARCHITECTURE | 5-layer pipeline, invariants, runbook | `README.md`, `docs/ARCHITECTURE.md` |
| C1-T03 Mosquitto | broker 2.1.2 on :1883, pub/sub verified by hand | live run, `mosquitto.conf` |
| C1-T04 device profiles | 5 ESP32 profiles (BME280/DHT22/PIR/ACS712/reed), rooms, MACs, QoS | `src/simulator/devices.py` |
| C1-T05 traffic generator | live run vs local broker, 262 events in 120 s | `src/simulator/traffic_gen.py` |
| C1-T06 storage | SQLite `mqtt_events`, UTC ISO8601, 3 indexes, WAL | `src/storage/db.py` |
| C1-T07 tests | 10/10 passing | commit `d2c4579` |
| C1-T08 CICIoT2023 download | 310 files ~8.5 GB at `data/raw/ciciot2023/` | 46,776,700 rows counted in EDA |
| C1-T09 EDA notebook | executed, all 8 sections, outputs saved | commit `75ce6f0`, `src/notebooks/01_ciciot_eda.ipynb` |
| C1-T10 demo dry-run | one-command launcher `demo.ps1`, 4 terminals, interactive control | commit `c844ea6` + live run |

### Key EDA findings carried into Checkpoint 2

- 39 features, schema identical across benign and attack files; no label column
  (folder name is the label — we assign it programmatically).
- Benign share: 2.35% of 46.7M rows — class imbalance is the first C2 decision.
- Constant columns to drop: `Telnet`, `SMTP` (benign), `Min` within SYN flood.
- DDoS+DoS+Mirai flooding = ~44.5M rows vs Recon 0.7M / Web 19K / BruteForce 13K —
  rules will ace flooding and struggle on the small classes; the ML model must
  close that gap. That measured difference is the benchmark table.

### Bugs found and fixed during this checkpoint

1. `publish_periodic()` missing `state` argument (runtime crash) — fixed `9ba9c91`.
2. Payload padding could truncate JSON mid-string (invalid payloads) — replaced
   with floor-only padding after measuring natural body sizes; test caught it (`d2c4579`).
3. SQLite connection used from the paho MQTT callback thread — fixed with
   `check_same_thread=False` + write lock (`6b2cc7b`).
4. Devices never published `online` status after a dropout (retained state
   stayed `offline`) — recovery hook added to the loop (`e785304`).

## Checkpoint 2 — Detection Engine v1 + Benchmark (23–29 Nov) — not started

Planned first move: `src/detection/features.py` on top of the stored
`mqtt_events` schema + CICIoT2023 loader with folder-derived labels.
