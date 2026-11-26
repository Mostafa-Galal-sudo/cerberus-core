# Cerberus-Core — Test Results Report

> **Generated:** 2026-11-26  
> **Platform:** Windows (win32)  
> **Python:** 3.14.3 · pytest 9.2.0 · pluggy 1.7.0  
> **Duration:** 226.99 s (03:46)  
> **Result:** ✅ **38 passed, 0 failed, 0 errors**

---

## Summary

| Test File | Tests | Passed | Failed |
|---|---|---|---|
| `tests/test_detection_data.py` | 7 | 7 | 0 |
| `tests/test_detection_hybrid.py` | 10 | 10 | 0 |
| `tests/test_detection_models.py` | 8 | 8 | 0 |
| `tests/test_lab_detection.py` | 2 | 2 | 0 |
| `tests/test_traffic_gen.py` | 11 | 11 | 0 |
| **Total** | **38** | **38** | **0** |

---

## 1. `tests/test_detection_data.py` — Feature Extraction & Dataset Loading

These tests cover `src/detection/features.py` and `src/detection/dataset.py`.  
They verify that raw SQLite events are correctly windowed, features are computed accurately, and dataset loading is unbiased and reproducible.

| # | Test Name | Status | What it verifies |
|---|---|---|---|
| 1 | `test_windows_from_simulated_db` | ✅ PASSED | `windows_from_db()` reads a real SQLite DB and groups events into 60-second windows; confirms each window has the 14 expected feature columns (including `topic_entropy`) with no NaN values |
| 2 | `test_category_mapping_covers_every_folder` | ✅ PASSED | Every sub-folder in `data/raw/ciciot2023/CSV/` maps to a known attack category; ensures `CATEGORY_MAP` in `dataset.py` is exhaustive and no folder is silently dropped as "unknown" |
| 3 | `test_sample_loads_both_classes_and_drops_constants` | ✅ PASSED | `load_sample()` returns rows from both benign (label=0) and attack (label=1) classes; constant-valued columns are dropped to prevent models from learning on degenerate features |
| 4 | `test_split_never_shares_a_capture_file` | ✅ PASSED | `partition()` ensures no CSV file appears in both train and test splits — guards against data leakage across the train/test boundary |
| 5 | `test_trailing_partial_window_rate_uses_actual_duration` | ✅ PASSED | The last (partial) time window uses its real elapsed duration as the denominator for `rate_per_sec`, not the full 60s — prevents systematic underestimation of rates in short trailing windows |
| 6 | `test_topic_entropy_zero_and_even_split` | ✅ PASSED | `topic_entropy` is 0.0 when all events share one topic (no diversity), and equals `log2(n)` when events are spread evenly across `n` topics (maximum diversity) |
| 7 | `test_load_sample_uses_seeded_random_sampling` | ✅ PASSED | `load_sample(seed=0)` uses seeded random row sampling (not the first N rows); same seed → identical sample; different seeds → different samples — removes capture-start bias |

---

## 2. `tests/test_detection_hybrid.py` — Hybrid Detector & Deviation Baseline

These tests cover `src/detection/hybrid.py` and `src/detection/fingerprint.py`.  
They verify the full detection pipeline: statistical anomaly detection, device fingerprinting, confidence scoring, and human-readable explanations.

| # | Test Name | Status | What it verifies |
|---|---|---|---|
| 1 | `test_baseline_flags_out_of_distribution_rows` | ✅ PASSED | `DeviationBaseline` raises an alert when a row is statistically far from the training distribution (high z-score on rate features) |
| 2 | `test_baseline_stays_quiet_on_benign_like_rows` | ✅ PASSED | `DeviationBaseline` does **not** alert on rows that look like the training data — confirms the false-positive rate is controlled |
| 3 | `test_baseline_drivers_name_the_shifted_features` | ✅ PASSED | `drivers()` ranks features by **unclipped** z-score so that features with extreme shifts (e.g. `Rate`) always appear in the top-k list; prevents ties at the clipping ceiling from omitting true drivers |
| 4 | `test_baseline_limit_is_positive_and_finite` | ✅ PASSED | The adaptive threshold (MAD-based, with std fallback) is always a positive finite number — prevents division-by-zero and ±inf thresholds on degenerate data |
| 5 | `test_hybrid_alerts_on_rules_and_on_deviation_alone` | ✅ PASSED | `HybridDetector` fires when **either** the rule engine triggers **or** the deviation baseline triggers — both signal paths are active |
| 6 | `test_hybrid_keeps_benign_quiet` | ✅ PASSED | `HybridDetector` does **not** alert on a normal benign window, confirming both detectors are simultaneously quiet on clean traffic |
| 7 | `test_hybrid_confidence_is_bounded_and_explained` | ✅ PASSED | `confidence` is always in `[0.0, 1.0]`; every alert includes a non-empty human-readable `explanation` string listing the reason(s) for the alert |
| 8 | `test_hybrid_fingerprint_signal_can_raise_an_alert` | ✅ PASSED | A device that deviates from its own historical fingerprint (learned per-device baseline) triggers an alert, even if rule and global-baseline detectors stay quiet |
| 9 | `test_fingerprint_min_windows_fallback_and_known` | ✅ PASSED | `DeviceFingerprint` returns `known()=False` and falls back to the global baseline until it has seen `min_windows` training samples for a device; `known()` becomes `True` only after enough data |
| 10 | `test_hybrid_flags_unknown_device_with_explanation` | ✅ PASSED | `HybridDetector.predict()` directly flags a device ID never seen during training with `severity="high"` and an explanation string containing `unknown_device:<id>` — the detector itself, not fingerprint.known(), raises this alert |

---

## 3. `tests/test_detection_models.py` — Rule Engine & Isolation Forest

These tests cover `src/detection/models.py`.  
They verify the rule-based detector, the Isolation Forest anomaly detector, and dataset splitting for training.

| # | Test Name | Status | What it verifies |
|---|---|---|---|
| 1 | `test_rule_engine_near_silent_on_benign` | ✅ PASSED | `RuleEngine` raises ≤5% false-positive rate on a large benign-like dataset — rules are tight enough not to spam alerts on normal traffic |
| 2 | `test_rule_engine_min_hits_trades_recall_for_precision` | ✅ PASSED | With `min_hits=2`, the rule engine requires two separate rule conditions to fire before alerting; this reduces false positives at the cost of some recall |
| 3 | `test_rule_engine_flags_rate_spike` | ✅ PASSED | A row with a very high `rate_per_sec` value correctly triggers the rate-spike rule; confirms the threshold and logic are wired correctly |
| 4 | `test_rule_engine_returns_one_reason_list_per_row` | ✅ PASSED | `predict()` returns one list of triggered rule names per input row; the output shape matches the input, and no reason lists are `None` |
| 5 | `test_isolation_forest_flags_shifted_rows` | ✅ PASSED | `IsolestForest` (trained on benign-like data) assigns anomaly predictions to rows whose features are shifted far outside the training distribution |
| 6 | `test_isolation_forest_stays_quiet_on_training_distribution` | ✅ PASSED | Most rows from the same distribution as the training set are **not** flagged as anomalies — contamination parameter is calibrated |
| 7 | `test_split_covers_single_file_folders_in_test` | ✅ PASSED | `partition()` handles the edge case where an attack category folder contains only one CSV file — that file still ends up in test (not silently dropped) |
| 8 | `test_rule_engine_mqtt_feature_set` | ✅ PASSED | `RuleEngine(feature_set="mqtt")` works with the full 14-feature MQTT feature vector; confirms `FEATURE_NAMES` and rule thresholds are compatible with the extended feature set including `topic_entropy` |

---

## 4. `tests/test_lab_detection.py` — End-to-End Lab Integration

These tests run the full pipeline against the **real lab SQLite database** (`data/lab/lab_traffic.db`) and the full CICIoT2023 benchmark dataset.  
They are the highest-level integration tests in the suite.

> [!NOTE]
> `test_benchmark_confusion_table_and_partition` reads all 309 CICIoT2023 CSV files (~8.5 GB).
> It requires the dataset to be downloaded to `data/raw/ciciot2023/CSV/`.
> This test alone accounts for most of the 226 s runtime.

| # | Test Name | Status | What it verifies |
|---|---|---|---|
| 1 | `test_lab_check_all_detectors_fire_on_anomalies` | ✅ PASSED | `lab_check.py` runs the rule engine, Isolation Forest, deviation baseline, and fingerprint detector against the real lab DB (which contains injected MQTT anomalies); confirms **all four** detectors produce at least one alert on the anomalous traffic |
| 2 | `test_benchmark_confusion_table_and_partition` | ✅ PASSED | Runs the full CICIoT2023 benchmark: trains all five classifiers (rules, rules_strict, iforest, baseline, hybrid), evaluates on the held-out test partition, and asserts that confusion matrix outputs include TP, FP, TN, FN counts for every model; also checks that the train/test partition is free of leakage |

---

## 5. `tests/test_traffic_gen.py` — MQTT Traffic Simulator

These tests cover `src/simulator/traffic_gen.py` and `src/simulator/anomalies.py`.  
They verify the simulated IoT device traffic generator and the live MQTT anomaly injectors.

| # | Test Name | Status | What it verifies |
|---|---|---|---|
| 1 | `test_schema_and_indexes_created` | ✅ PASSED | `TrafficGen` creates the SQLite DB with the correct table schema and indexes on `(timestamp, device_id)` — fast range queries for windowing are supported from the start |
| 2 | `test_save_event_roundtrip` | ✅ PASSED | An event written via `save_event()` can be read back with identical field values — confirms serialization, storage, and deserialization are lossless |
| 3 | `test_payload_sizes_stay_in_profile_range` | ✅ PASSED | Generated event payloads have byte lengths within the min/max bounds declared in the device profile — no oversized or empty payloads slip through |
| 4 | `test_climate_stays_near_baseline` | ✅ PASSED | Simulated climate sensor readings (temperature, humidity) stay within ±3σ of the configured baseline; validates the sensor noise model |
| 5 | `test_climate_dropout_returns_none_sometimes` | ✅ PASSED | The climate sensor occasionally returns `None` (simulating a sensor dropout/offline event) according to the configured dropout probability |
| 6 | `test_power_toggle_changes_state` | ✅ PASSED | Calling `toggle()` on a simulated smart plug switches its state between ON and OFF correctly |
| 7 | `test_event_payload_values` | ✅ PASSED | The JSON payload of a generated event contains the expected keys and value types for each device type (climate, power, motion) |
| 8 | `test_status_payload_shape` | ✅ PASSED | The periodic device-status heartbeat payload has the correct structure (device_id, uptime, firmware, signal strength, etc.) |
| 9 | `test_summary_aggregates_by_device_and_direction` | ✅ PASSED | `summarize()` correctly groups events by `(device_id, direction)` and counts them; the resulting aggregation matches the expected row count |
| 10 | `test_log_command_records_operator` | ✅ PASSED | Operator commands (e.g. remotely toggling a device) are logged to the DB with the correct `operator` field — the audit trail is complete |
| 11 | `test_anomaly_injectors_log_events_without_broker` | ✅ PASSED | `RateFloodInjector`, `PayloadBloatInjector`, and `RogueDeviceInjector` from `src/simulator/anomalies.py` all write events to the SQLite DB **without** requiring a live MQTT broker — they work in broker-less lab mode |

---

## Benchmark Results (from `results/benchmark_ciciot_v1.md`)

Evaluated on CICIoT2023 held-out test partition (seeded random sampling, `seed=0`):

| Model | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| `rules` | — | — | 0.958 | — |
| `rules_strict` | — | — | 0.439 | — |
| `iforest` | — | — | 0.604 | — |
| `baseline` | — | — | 0.926 | — |
| `hybrid` | — | — | 0.956 | — |

> Full confusion matrices and per-category recall are in [`results/benchmark_ciciot_v1.md`](benchmark_ciciot_v1.md).

---

## Notes

- **CICIoT2023 benchmark** (test 4-2) reads all 309 CSV files and dominates the total runtime (~220 s of the 227 s total).
- All **Rozan/** files are excluded from tests and are never read, staged, or referenced.
- The `.venv` uses Python 3.14.3; pytest-anyio and platformdirs plugins are present but not actively used by these tests.
- Run with: `.venv\Scripts\python -m pytest tests -v`
