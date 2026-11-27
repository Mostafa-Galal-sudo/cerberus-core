# CERBERUS acceptance stress benchmark

Generated 2026-11-27T17:59:55+00:00 · simulation-only · no external targets

| Section | Gate | Result |
|---|---|---|
| adapter | all_failures_handled | PASS |
| adapter | no_uncaught_exception | PASS |
| adapter | retry_is_bounded | PASS |
| adapter | circuit_opens_and_blocks | PASS |
| adapter | budget_never_exceeded | PASS |
| adapter | no_secret_leak | PASS |
| adapter | ab_uses_both_and_is_stable | PASS |
| ollama | all_requests_completed | PASS |
| ollama | json_validity_at_least_90pct | PASS |
| ollama | tool_calls_at_least_90pct | PASS |
| ollama | p95_latency_under_30s | PASS |
| dataset | benchmark_completed | PASS |
| dataset | hybrid_f1_at_least_0_85 | PASS |
| dataset | hybrid_fpr_at_most_0_10 | PASS |
| live | launcher_started | PASS |
| live | exit_code_zero | PASS |
| live | db_integrity_ok | PASS |
| live | no_error_markers | PASS |
| live | events_and_incidents_present | PASS |
| live | correlations_at_least_95pct | PASS |
| live | no_duplicate_incident_chains | PASS |

## Measured values

### adapter

```json
{
  "scenarios": 7,
  "handled": 7,
  "uncaught": 0,
  "attempts_total": 11,
  "expected_attempts": 11,
  "circuit_opened": true,
  "circuit_blocked": true,
  "half_open_probe_ok": true,
  "budget_violations": 0,
  "secret_leaks": 0,
  "ab_unique_providers": 2,
  "ab_stable": true
}
```

### ollama

```json
{
  "models_available": [
    "qwen3-vl:4b-instruct"
  ],
  "requests": 20,
  "json_valid": 20,
  "json_valid_rate": 1.0,
  "tool_requests": 4,
  "tool_success": 4,
  "tool_success_rate": 1.0,
  "fallbacks": 0,
  "tokens": 1500,
  "latency_ms_p50": 2396.77,
  "latency_ms_p95": 8588.37,
  "latency_ms_max": 29788.24
}
```

### dataset

```json
{
  "sampled_rows_per_file": 200,
  "train_rows": 400,
  "test_rows": 61400,
  "hybrid_f1": 0.9793,
  "hybrid_fpr": 0.06,
  "rules_f1": 0.9789,
  "elapsed_s": 266.24
}
```

### live

```json
{
  "injectors": 5,
  "stop_after_seconds": 90,
  "exit_code": 0,
  "elapsed_s": 140.22,
  "db_path": "F:\\UserData\\Downloads\\Cerberus\\cerberus-core\\data\\lab\\live_traffic_20261127_195736.db",
  "events": 480,
  "incidents": 23,
  "events_per_s": 3.42,
  "incidents_per_s": 0.164,
  "attack_correlations": 20,
  "matched_correlations": 20,
  "correlation_completeness": 1.0,
  "duplicate_incident_correlations": 0,
  "denies": 13,
  "llm_modes": {
    "fallback": 23
  },
  "integrity_check": "ok",
  "detection_to_incident_ms_p50": 3097.0,
  "detection_to_incident_ms_p95": 19130.0,
  "error_markers": [],
  "log_tail": "njectors ready: e2-inj-1, e2-inj-2, e2-inj-3, e2-inj-4, e2-inj-5\n\n==> Starting Cerberus SOC Dashboard on http://127.0.0.1:8000\n    [OK] Dashboard live (E2 concurrent simulated SOC) -- total_events=157  open_incidents=0\n    [OK] Release token (X-Cerberus-Token): [REDACTED]\n\n============================================================\n  Cerberus SOC Dashboard:  http://127.0.0.1:8000\n\n  API endpoints:\n    /api/health      -- system health + KPIs\n    /api/overview    -- device grid + KPIs\n    /api/incidents   -- all incidents\n    /api/isolations  -- isolation registry\n    /api/audit       -- policy audit log\n    /api/stream      -- SSE live feed\n\n  Live DB: F:\\UserData\\Downloads\\Cerberus\\cerberus-core\\data\\lab\\live_traffic_20261127_195736.db\n  Component logs: C:\\Users\\mosta\\AppData\\Local\\Temp\\cerberus_live_*.out.log\n  Press Ctrl+C to stop the entire simulated SOC.\n============================================================\n\n    [!!] StopAfterSeconds=90 reached; shutting down live run\n  Live run summary: events=480 incidents=23 open_incidents=13 active_isolations=5 denies=13 attacks=20 event_correlations=20 audit_correlations=20 event_injectors=5 audit_injectors=5\n\nDashboard stopped.\n\n"
}
```

## Protocol

- Adapter section uses injected failures only; no provider key is required.
- Ollama section calls the real local OpenAI-compatible endpoint when reachable.
- Dataset section samples CICIoT2023 at file level and never trains on attack rows.
- Live section runs `demo.ps1 -Live` against a fresh SQLite DB and inspects it afterwards.
- CLI: `src/evaluation/stress_benchmark.py --sections adapter,ollama,dataset,live --ollama-requests 20 --dataset-rows 200 --live-injectors 5 --live-seconds 90`

**Overall:** PASS
