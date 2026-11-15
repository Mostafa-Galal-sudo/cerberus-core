# data/

All datasets and captures. **Nothing in this tree is committed to Git.**

| Subfolder | Content | Used by |
|-----------|---------|---------|
| `raw/` | CICIoT2023 CSVs exactly as downloaded | EDA + ML training (Checkpoint 2) |
| `processed/` | Cleaned / sampled / feature-mapped CSVs derived from `raw/` | Detection engine |
| `lab/` | Team-collected PCAPs, MQTT logs and attack captures (Checkpoint 4+) | Lab re-validation (Checkpoint 4/5) |

Naming convention: `<source>_<date>_<label>.<ext>` (e.g. `ciciot_2026-11-20_ddos_subset.csv`, `lab_2026-12-09_mqtt_flood.pcap`).
