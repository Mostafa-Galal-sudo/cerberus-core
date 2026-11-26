# Cerberus-Core — Test Results Report

> **Generated:** 2026-11-26
> **Platform:** Windows (win32)
> **Python:** 3.14.3 · pytest 9.2.0
> **Command:** `.venv\Scripts\python -m pytest tests -q` (run from the repository root)
> **Duration:** 383.70 s (06:23)
> **Result:** 71 passed, 0 failed, 0 errors

This report records the final verification run after the H2/H3, M1–M6 and L1–L4 fixes.
The earlier baseline run was `1 failed, 63 passed in 316.88s`; the failure was
`tests/test_lab_detection.py::test_lab_check_all_detectors_fire_on_anomalies`
(`assert 0 == 3`) caused by the local `fingerprint.py` regression. Restoring the
committed MAD/standard-deviation fallback resolved it without changing the
committed detection logic.

---

## Summary

| Test File | Tests | Passed | Failed |
|---|---:|---:|---:|
| `tests/test_agent_tools.py` | 2 | 2 | 0 |
| `tests/test_agents.py` | 7 | 7 | 0 |
| `tests/test_closed_loop.py` | 10 | 10 | 0 |
| `tests/test_dashboard.py` | 2 | 2 | 0 |
| `tests/test_detection_data.py` | 7 | 7 | 0 |
| `tests/test_detection_hybrid.py` | 10 | 10 | 0 |
| `tests/test_detection_models.py` | 8 | 8 | 0 |
| `tests/test_lab_detection.py` | 2 | 2 | 0 |
| `tests/test_persistence.py` | 4 | 4 | 0 |
| `tests/test_policy.py` | 4 | 4 | 0 |
| `tests/test_response.py` | 3 | 3 | 0 |
| `tests/test_traffic_gen.py` | 12 | 12 | 0 |
| **Total** | **71** | **71** | **0** |

---

## 1. `tests/test_agent_tools.py` — Read-only Agent Tools & Audit Trail

| # | Test | Status | Verifies |
|---:|---|---|---|
| 1 | `test_db_tools_and_audit_and_incident_trail` | PASSED | Event queries and incident-history queries are audited and appended to the incident timeline; incident opening itself is now an audited `open_incident` action (3 audit rows). |
| 2 | `test_fingerprint_tool_and_pcap_graceful_fallback` | PASSED | Deviation report identifies a known device; missing PCAP data degrades gracefully instead of raising. |

## 2. `tests/test_agents.py` — Defense/Attack Agents & Policy Boundaries

| # | Test | Status | Verifies |
|---:|---|---|---|
| 1 | `test_defense_agent_fallback_when_no_api_key` | PASSED | Without `GROQ_API_KEY` the defense agent uses deterministic investigation and stays policy-bounded. |
| 2 | `test_defense_agent_llm_tool_calling_and_policy_isolation` | PASSED | Mocked Groq tool-calling path writes the incident timeline and isolates only through an `ALLOW` decision. |
| 3 | `test_defense_agent_falls_back_on_api_exception` | PASSED | An API exception falls back to deterministic investigation. |
| 4 | `test_attack_agent_respects_policy_gate_and_injects_in_lab_scope` | PASSED | DeepSeek plan is authorized before injection; out-of-scope targets are denied and no events are written. |
| 5 | `test_defense_agent_falls_back_on_sdk_import_failure` | PASSED | SDK import failure is caught in `_get_client()` and reported as a fallback with an error (M4). |
| 6 | `test_attack_agent_falls_back_on_sdk_import_failure` | PASSED | Same graceful degradation for the attack agent (M4). |
| 7 | `test_log_alert_denial_is_not_recorded_as_logged` | PASSED | A denied `log_alert` writes a `policy_denied` timeline event and never marks the incident `outcome="logged"` (M3). |

## 3. `tests/test_closed_loop.py` — In-process End-to-end Loop

| # | Test | Status | Verifies |
|---:|---|---|---|
| 1 | `test_loop_run_once_produces_incident` | PASSED | One attack → detect → defend cycle creates an incident. |
| 2 | `test_loop_attack_events_written_to_db` | PASSED | Injected attack events are persisted to `mqtt_events`. |
| 3 | `test_loop_incident_opened_with_correct_device` | PASSED | Incident device matches the attack target. |
| 4 | `test_loop_policy_audit_has_allow_for_attack_action` | PASSED | Attack execution carries an `ALLOW` audit decision. |
| 5 | `test_loop_isolation_recorded_on_high_severity` | PASSED | High-severity detections produce a real isolation record. |
| 6 | `test_loop_no_bypass_policy_on_isolation` | PASSED | Isolation cannot be executed without a policy decision (M1/M2). |
| 7 | `test_loop_fallback_works_without_api_keys` | PASSED | The loop completes with no LLM credentials. |
| 8 | `test_loop_on_event_callback_fires` | PASSED | SSE/event callback receives loop updates. |
| 9 | `test_loop_run_multiple_cycles` | PASSED | Three consecutive cycles remain consistent. |
| 10 | `test_make_loop_convenience_factory` | PASSED | `make_loop()` wiring works with a DB path. |

## 4. `tests/test_dashboard.py` — SOC Dashboard & Release Endpoint

| # | Test | Status | Verifies |
|---:|---|---|---|
| 1 | `test_dashboard_endpoints_and_release_flow` | PASSED | Health/overview/incidents/isolations/audit endpoints respond; release requires `X-Cerberus-Token`, rejects missing/wrong tokens with 401, accepts the configured token, and SSE payload contains `audit`. |
| 2 | `test_dashboard_release_fails_closed_without_configured_token` | PASSED | With no `CERBERUS_DASHBOARD_TOKEN`, release returns 503 `DASHBOARD_AUTH_NOT_CONFIGURED` (H3). |

## 5. `tests/test_detection_data.py` — Features, Dataset & Leakage-free Splits

| # | Test | Status | Verifies |
|---:|---|---|---|
| 1 | `test_windows_from_simulated_db` | PASSED | Sliding windows are produced from stored events. |
| 2 | `test_category_mapping_covers_every_folder` | PASSED | Every CICIoT2023 attack folder maps to a category. |
| 3 | `test_sample_loads_both_classes_and_drops_constants` | PASSED | Sampled data includes both classes and drops constant columns once. |
| 4 | `test_split_never_shares_a_capture_file` | PASSED | Train/test split is file-level; no capture leaks across sides. |
| 5 | `test_trailing_partial_window_rate_uses_actual_duration` | PASSED | Partial trailing windows use their real duration for rate calculation. |
| 6 | `test_topic_entropy_zero_and_even_split` | PASSED | Entropy is 0 for a single topic and maximal for an even split. |
| 7 | `test_load_sample_uses_seeded_random_sampling` | PASSED | Sampling is reproducible with a fixed seed. |

## 6. `tests/test_detection_hybrid.py` — Deviation Baseline, Fingerprint & Hybrid

| # | Test | Status | Verifies |
|---:|---|---|---|
| 1 | `test_baseline_flags_out_of_distribution_rows` | PASSED | Population baseline fires on shifted rows. |
| 2 | `test_baseline_stays_quiet_on_benign_like_rows` | PASSED | Baseline stays quiet on benign-like rows. |
| 3 | `test_baseline_drivers_name_the_shifted_features` | PASSED | Explanation names the deviating features. |
| 4 | `test_baseline_limit_is_positive_and_finite` | PASSED | Fitted limit is finite and positive. |
| 5 | `test_hybrid_alerts_on_rules_and_on_deviation_alone` | PASSED | Hybrid union keeps both detection branches. |
| 6 | `test_hybrid_keeps_benign_quiet` | PASSED | Benign traffic does not trigger hybrid alerts. |
| 7 | `test_hybrid_confidence_is_bounded_and_explained` | PASSED | Confidence is bounded and carries an explanation. |
| 8 | `test_hybrid_fingerprint_signal_can_raise_an_alert` | PASSED | Per-device fingerprint signal can independently raise an alert. |
| 9 | `test_fingerprint_min_windows_fallback_and_known` | PASSED | Fingerprint handles insufficient baselines and known devices (H2 regression coverage). |
| 10 | `test_hybrid_flags_unknown_device_with_explanation` | PASSED | Unknown device produces an explained alert. |

## 7. `tests/test_detection_models.py` — Rules & Isolation Forest

| # | Test | Status | Verifies |
|---:|---|---|---|
| 1 | `test_rule_engine_near_silent_on_benign` | PASSED | Rules do not fire on benign traffic. |
| 2 | `test_rule_engine_min_hits_trades_recall_for_precision` | PASSED | Two-hit mode raises precision and lowers recall. |
| 3 | `test_rule_engine_flags_rate_spike` | PASSED | Rate spike is detected. |
| 4 | `test_rule_engine_returns_one_reason_list_per_row` | PASSED | One reason list is returned per evaluated row. |
| 5 | `test_isolation_forest_flags_shifted_rows` | PASSED | Isolation Forest flags shifted rows. |
| 6 | `test_isolation_forest_stays_quiet_on_training_distribution` | PASSED | It stays quiet on the training distribution. |
| 7 | `test_split_covers_single_file_folders_in_test` | PASSED | Single-file folders still reach the test partition. |
| 8 | `test_rule_engine_mqtt_feature_set` | PASSED | Rules work on the shared MQTT feature set. |

## 8. `tests/test_lab_detection.py` — Lab Check & Benchmark Helpers

| # | Test | Status | Verifies |
|---:|---|---|---|
| 1 | `test_lab_check_all_detectors_fire_on_anomalies` | PASSED | With non-overlapping 60 s windows (M5): `train_windows=177`, `normal_windows=57`, `flood_windows=3` with 3 rule/FP/hybrid alerts each, `bloat_windows=3` with 3 rule/FP alerts, `rogue_windows=3`, rogue device unknown. |
| 2 | `test_benchmark_confusion_table_and_partition` | PASSED | Confusion table rendering and partition helpers behave as expected. |

## 9. `tests/test_persistence.py` — Schema, Config & Incident Timeline

| # | Test | Status | Verifies |
|---:|---|---|---|
| 1 | `test_extended_schema_tables_created` | PASSED | All five C3 tables are created. |
| 2 | `test_get_db_path_uses_env_and_override` | PASSED | `CERBERUS_DB_PATH` and explicit override resolve correctly. |
| 3 | `test_incident_opening_requires_policy_allow` | PASSED | `create_incident` denies an unauthorized actor, creates no incident, and logs one `DENY` audit row (M2). |
| 4 | `test_incident_lifecycle_and_ordered_timeline` | PASSED | Incident lifecycle produces an ordered evidence timeline. |

## 10. `tests/test_policy.py` — Allowlist, Scope, Rate Limit

| # | Test | Status | Verifies |
|---:|---|---|---|
| 1 | `test_policy_allows_valid_defense_and_attack_actions` | PASSED | Valid defense/attack actions are `ALLOW` and written to SQLite + JSONL audit. |
| 2 | `test_policy_blocks_cross_role_and_unknown_actions` | PASSED | Cross-role and unknown actions are denied. |
| 3 | `test_policy_blocks_wildcards_and_out_of_scope_targets_and_topics` | PASSED | Wildcards and out-of-scope targets/topics are denied. |
| 4 | `test_policy_rate_limiter_enforces_window_and_recovers` | PASSED | Sliding-window rate limit is enforced and recovers. |

## 11. `tests/test_response.py` — Isolation Registry Execution Primitive

| # | Test | Status | Verifies |
|---:|---|---|---|
| 1 | `test_isolate_and_release_require_policy_and_update_incident` | PASSED | Attack actor is denied; defense actor isolates and releases with the incident updated. |
| 2 | `test_registry_rejects_execution_without_allow_decision` | PASSED | `activate()` and `release()` reject a `DENY` decision directly; no isolation state is created (M1). |
| 3 | `test_isolation_expiry_steps_down_stale_records` | PASSED | Stale isolations step down on expiry. |

## 12. `tests/test_traffic_gen.py` — Simulator & Anomaly Injection

| # | Test | Status | Verifies |
|---:|---|---|---|
| 1 | `test_schema_and_indexes_created` | PASSED | Storage schema and indexes exist. |
| 2 | `test_save_event_roundtrip` | PASSED | Events round-trip through SQLite. |
| 3 | `test_payload_sizes_stay_in_profile_range` | PASSED | Payload sizes respect device profiles. |
| 4 | `test_climate_stays_near_baseline` | PASSED | Climate sensor stays near baseline. |
| 5 | `test_climate_dropout_returns_none_sometimes` | PASSED | Simulated offline behavior is exercised. |
| 6 | `test_power_toggle_changes_state` | PASSED | Plug state toggles correctly. |
| 7 | `test_event_payload_values` | PASSED | Event payload fields are valid. |
| 8 | `test_status_payload_shape` | PASSED | Status payload shape is valid. |
| 9 | `test_summary_aggregates_by_device_and_direction` | PASSED | Summary aggregates by device and direction. |
| 10 | `test_log_command_records_operator` | PASSED | Operator commands are recorded. |
| 11 | `test_anomaly_injectors_log_events_without_broker` | PASSED | Flood/bloat/rogue injectors write events when given real `ALLOW` decisions. |
| 12 | `test_anomaly_injector_rejects_denied_decision` | PASSED | An injector given a `DENY` decision writes zero events (M1). |

---

## Evidence boundary

- **Verified execution:** the 71-test run above, plus a separate `run_lab_check(seed=0)` producing the window counts quoted in section 8.
- **Not verified in this run:** live MQTT broker injection, live Groq/DeepSeek API calls (mocked or fallback paths only), and a live `demo.ps1` launch.
- **User-edited H1 files:** `src/dashboard/static/index.html`, `src/loop/__init__.py`, and untracked `src/dashboard/static/image.png` were left for the user; the dashboard test exercises the server-side H3 behavior and the minimal L3/H3 changes already present in the working copy.
