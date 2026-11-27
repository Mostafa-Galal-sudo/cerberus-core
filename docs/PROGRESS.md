# PROGRESS — weekly log

One entry per checkpoint: what shipped, evidence, what slipped.
The task-level plan lives in `CERBERUS_WEEKLY_CHECKPOINTS_TASKS.md`.

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
| C1-T08 CICIoT2023 download | 310 CSV files / 9.66 GB measured at `data/raw/ciciot2023/CSV/` | 46,776,700 rows counted in EDA |
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

## Checkpoint 2 — Detection Engine v1 + Benchmark (23–29 Nov) — ✅ COMPLETE 26 Nov

| Task | Result | Evidence |
|------|--------|----------|
| C2-T01 features | 14 sliding-window MQTT behavioral features | `src/detection/features.py` |
| C2-T02 dataset loader | CICIoT2023 folder-label loader + file-level split | `src/detection/dataset.py` |
| C2-T03 rules engine | `RuleEngine` (`ciciot` 8 rules, `mqtt` 6 rules) | `src/detection/rules_engine.py` |
| C2-T04 ML model | `AnomalyModel` (Isolation Forest + IQR scaling) | `src/detection/ml_model.py` |
| C2-T05 fingerprint | `DeviceFingerprint` (per-device median/MAD baseline) | `src/detection/fingerprint.py` |
| C2-T06 hybrid detector | `DeviationBaseline` + `HybridDetector` (confidence + severity + explanation) | `src/detection/baseline.py`, `src/detection/hybrid.py` |
| C2-T07 benchmark harness | Benign-only fit, file-level split, 5-detector comparison | `src/evaluation/benchmark.py` |
| C2-T08 CICIoT2023 benchmark | `hybrid` 0.956 F1, `baseline` 0.926 F1, `rules` 0.958 F1, `iforest` 0.604 F1 + confusion matrices (random sampling `seed=0`) | `results/benchmark_ciciot_v1.md` |
| C2-T09 lab sanity check | Live `traffic_gen.py` + `anomalies.py` (`flood`/`bloat`/`rogue`) + synthetic check | `src/simulator/anomalies.py`, `src/evaluation/lab_check.py`, `tests/test_lab_detection.py` |

### Bugs found and fixed during this checkpoint

1. `DeviationBaseline.drivers()` tie-breaking at `SCORE_CLIP = 20.0` omitted `'Rate'` when multiple features saturated — fixed by ranking on unclipped z-scores.
2. `DeviceFingerprint._baseline()` fell back directly to `0.01 * median` when `MAD == 0`, inflating `threshold_` to `20.0` on discrete event counts — fixed by falling back to `std` before `max(|median| * 0.05, 1e-3)`.
3. `lab_check.py` compared epoch `window_start` against relative `TRAIN_END = 1800.0`, producing an empty training frame — fixed by subtracting `BASE.timestamp()`.
4. `features.py` trailing partial window divided `rate_per_sec` by full `window_sec` — fixed to divide by actual tail duration; added `topic_entropy` (14 features).
5. `HybridDetector.predict()` did not flag unrecognized devices on its own — added `unknown_device:<id>` detection + explanation when `fingerprint` is attached.
6. `dataset.load_sample()` took the first `nrows` per CSV (capture-start bias) — switched to seeded random sampling (`seed=0`), improving `Recon` hybrid recall from `0.110` to `0.230`.

## Checkpoint 3 — Policy Gate, Agents, Response & SOC Dashboard (26 Nov) — COMPLETE

| Task | Result | Evidence |
|------|--------|----------|
| C3-T01 policy gate | `PolicyGate`: allowlist, lab scope, sliding-window rate limit, append-only SQLite/JSONL audit | `src/policy/`, `tests/test_policy.py` |
| C3-T02 agent tools | Read-only `db_tools`, `fingerprint_tools`, `pcap_tools` (audit + timeline logged) | `src/agents/tools/`, `tests/test_agent_tools.py` |
| C3-T03 incidents + persistence | Extended SQLite schema (`policy_audit`, `incidents`, `incident_events`, `isolations`) + `IncidentStore` | `src/storage/db.py`, `src/incidents/`, `tests/test_persistence.py` |
| C3-T04 defense agent | Groq API tool-calling investigation + `PolicyGate` isolation | `src/agents/defense_agent.py`, `tests/test_agents.py` |
| C3-T05 attack agent | DeepSeek API scenario proposal -> `PolicyGate` -> `src/simulator/anomalies.py` | `src/agents/attack_agent.py`, `tests/test_agents.py` |
| C3-T06 response isolation | Simulated isolation + TTL expiry/step-down via `IsolationRegistry` | `src/response/`, `tests/test_response.py` |
| C3-T07 SOC dashboard | FastAPI + SSE + CyFocus-styled dark SOC UI (KPIs, devices, incidents drawer, isolations, audit) | `src/dashboard/`, `tests/test_dashboard.py` |
| C3-T09 fallback mode | Deterministic rules-only investigation & attack plan when LLM keys missing/rate-limited | `src/agents/fallback.py`, `tests/test_agents.py` |
| C3-T08 closed loop | In-process attack -> detect -> defend runner + 10 integration tests | `src/loop/runner.py`, `tests/test_closed_loop.py`, commit `d8db434` |
| C3-T10 E2E demo | Single `demo.ps1` launcher: seed traffic, run 3 loop cycles, start SOC dashboard | `demo.ps1`, commit `4acc5d0` |

## Checkpoint 3-Extended — E1 Continuous Simulated SOC — ✅ IMPLEMENTED 27 Nov

Additive work only: C1, C2, and C3 evidence above is unchanged. Mode remains simulation-only;
no physical ESP32, RF, CSI, or SDR measurement is implied.

| Item | Result | Evidence |
|------|--------|----------|
| E1 launcher | `.\demo.ps1 -Live` starts the continuous stack; plain `.\demo.ps1` still runs the C3 three-cycle demo. Broker preflight, fresh timestamped DB, readiness waits, cleanup, and a supervised `-StopAfterSeconds` control were added. | `demo.ps1`; PowerShell parser reported `demo.ps1 parse OK`; launcher wiring asserted in `tests/test_live_pipeline.py` |
| E1 live stack | `src.live.subscriber` is the sole writer of `mqtt_events`; publisher, seed, and injector use real local MQTT sockets; worker reads subscriber-written rows and drives `DefenseAgent -> PolicyGate`; one-line DB summary via `src.live.summary`. | `src/live/*.py`; component logs in `%TEMP%\cerberus_live_*.out.log` |
| E1 traffic-generator change | `traffic_gen.generate()` gained `persist=False`, custom `client_id`, optional `stop_event`, indefinite mode, and UTC-prefixed logs. Default C3 behaviour is preserved. | `src/simulator/traffic_gen.py`; default launcher path asserted by test |
| E1 robustness fixes | SQLite connections now use a `30s` busy timeout for multi-process writers; retained MQTT messages are skipped; devices without a fitted benign baseline do not receive deviation alerts; injector logs `ALLOW`/`DENY` from `PolicyDecision.allowed`, not the nonexistent `verdict` attribute. | `src/storage/db.py`, `src/live/subscriber.py`, `src/live/worker.py`, `src/live/injector.py`; observed errors and fixes below |
| E1 tests | Full suite green. | `& .\.venv\Scripts\python.exe -m pytest tests -q` -> `76 passed in 56.08s`; focused `tests/test_live_pipeline.py` -> `5 passed` |
| E1 final supervised run | Continuous MQTT traffic, four policy-bounded attacks, incidents, isolations, and denies all persisted in a fresh DB. | `.\demo.ps1 -Live -StopAfterSeconds 70`; DB `data/lab/live_traffic_20261127_172303.db`; `src.live.summary` -> `events=149 incidents=7 open_incidents=2 active_isolations=3 denies=0 attacks=4` |
| E1 injector evidence | Four distinct attacks were allowed and injected over MQTT with identifiable attack IDs. | `%TEMP%\cerberus_live_injector.out.log`: `E1-flood-0000`, `E1-bloat-0001`, `E1-rogue-0002`, `E1-flood-0003`, each `injected=20 verdict=ALLOW` |
| E1 dashboard + SSE | APIs and one-shot SSE stream served the same live DB. | Endpoint run DB `data/lab/live_traffic_20261127_172440.db`: during run `/api/health` `status=ok events=73 open=0`, `/api/overview` `kpis_events=73 series_buckets=15`, `/api/incidents` `count=3`; `GET /api/stream?once=true` HTTP `200`, `48,373` bytes containing `"kpis"`, `"devices"`, `"incidents"`, `"isolations"`, `"audit"`; run summary at shutdown `events=145 incidents=8 open_incidents=2 active_isolations=3 denies=2 attacks=4` |
| E1 browser DOM | The UI did not fall back to simulated data during a live run. | Browser run DB `data/lab/live_traffic_20261127_172652.db`: DOM at `http://127.0.0.1:8000` showed `#live-label = "Live · 1s ago"`, `#live-banner.hidden = true`, and no `Simulated data` text; run summary at shutdown `events=151 incidents=8 open_incidents=2 active_isolations=3 denies=2 attacks=4` |
| E1 agent mode | No provider keys were configured; both agents used deterministic fallback. This is an outage/fallback mode, not an LLM A/B claim. | Live logs and `/api/health` `llm_mode.groq=fallback`, `llm_mode.deepseek=fallback` |

### Observed failures fixed during E1

1. `Start-LiveProc` returned a `Process` object, leaving log paths empty and breaking readiness waits — fixed by returning the entry object with `Proc`, `Out`, and `Err`.
2. Subscriber logged `ready` on CONNECT before SUBACK, so the first baseline messages could be lost — fixed by moving `ready` to `on_subscribe`.
3. Injector crashed on `PolicyDecision.verdict` — fixed to derive the verdict from `decision.allowed`.
4. Multi-process SQLite writes produced `database is locked` — fixed with connection timeout plus `PRAGMA busy_timeout = 30000`.
5. Direct DB logging in `traffic_gen.py` and retained messages from earlier runs polluted fresh live DBs — fixed by `persist=False` and subscriber-side retained-message skip.
6. Live DB summary quoted SQL incorrectly inside PowerShell — replaced with `src.live.summary --db <path>`.
7. A worker test saw fewer baseline windows than expected — fixed by widening the seeded benign window; full suite then passed.

### E1 limits / not claimed

- `-StopAfterSeconds` is only a supervised stop mechanism used for verification; the normal documented run is operator-stopped `.\demo.ps1 -Live`.
- No GROQ/DEEPSEEK keys were present, so no live-provider or A/B result is claimed.
- No physical device, RF, CSI, PHY fingerprint, or SDR measurement was performed.
- E3 provider adapter, E4 multi-protocol ingestion, E5 protocol controls, E6 capture, and E7 adaptation remain unimplemented.

## Checkpoint 3-Extended — E2 Concurrent Attacks — ✅ IMPLEMENTED 27 Nov

Additive to E1: the C1, C2, C3, and E1 evidence above is unchanged. Mode remains simulation-only;
every attack target is inside the lab allowlist and every event is carried by local MQTT sockets.

| Item | Result | Evidence |
|------|--------|----------|
| E2 launcher | `.\demo.ps1 -Live -ConcurrentInjectors <1..5>` keeps N=1 on the E1 path and starts dedicated injectors for N=3/5. The worker receives `--fanout` only for N>1. Invalid counts fail fast. | `demo.ps1`; PowerShell parser reported `demo.ps1 parse OK`; launcher wiring asserted in `tests/test_live_pipeline.py` |
| E2 identity and scope | Five `E2_SPECS` entries have distinct injector IDs, MQTT client IDs, lab targets, topics, and `injector:<id>` rate keys. The audit actor remains `attack`, so the existing allowlist stays authoritative. | Final injector logs `%TEMP%\cerberus_e2_n3_inj_*.out.log` and `%TEMP%\cerberus_e2_n5_inj_*.out.log`; final N=5 DB `policy_audit` shows five distinct targets and five distinct rate keys |
| E2 correlation storage | `mqtt_events` gained `correlation_id`/`injector_id` with a legacy-column migration and index; attack payloads, subscriber rows, and `policy_audit.context_json` carry the same IDs. | `src/storage/db.py`, `src/live/injector.py`, `src/live/subscriber.py`, `src/policy/gate.py`; migration, payload, and rate-key tests in `tests/test_live_pipeline.py` |
| E2 fan-out | The worker groups detections by `correlation_id`, dispatches one incident chain per attack through `DefenseAgent -> PolicyGate`, and deduplicates across polls. | `src/live/worker.py`; final worker logs: N=3 `15` fan-out lines / `15` unique correlation keys / `0` duplicates, N=5 `24` / `24` / `0`; incident detection evidence keys match |
| E2 tests | Full suite green, including the custom-target regression and fan-out deduplication tests. | `& .\.venv\Scripts\python.exe -m pytest tests -q` -> `82 passed in 270.32s`; focused `tests/test_live_pipeline.py` -> `11 passed in 7.69s` |
| E2 N=3 supervised run | Three concurrent injectors, 12 attacks, correlated events, incidents, isolations, and policy denies persisted in a fresh DB. | `.\demo.ps1 -Live -ConcurrentInjectors 3 -StopAfterSeconds 110`; DB `data/lab/live_traffic_20261127_175843.db`; `src.live.summary` -> `events=315 incidents=15 open_incidents=5 active_isolations=4 denies=5 attacks=12 event_correlations=12 audit_correlations=12 event_injectors=3 audit_injectors=3` |
| E2 N=5 supervised run | Five concurrent injectors, 20 attacks, and all five targets reached the subscriber and the audit log. | `.\demo.ps1 -Live -ConcurrentInjectors 5 -StopAfterSeconds 110`; DB `data/lab/live_traffic_20261127_180119.db`; `src.live.summary` -> `events=482 incidents=24 open_incidents=14 active_isolations=5 denies=13 attacks=20 event_correlations=20 audit_correlations=20 event_injectors=5 audit_injectors=5` |
| E2 per-attack chain | Every audit correlation has matching MQTT rows and incident detection evidence; no correlation was opened twice, and SQLite stayed consistent. | N=3: `12/12/12` audit/event/incident correlations, `0` missing, `0` duplicates, `20` event rows per correlation. N=5: `20/20/24` (the extra incident correlations are unattributed detections), `0` missing, `0` duplicates, `20` event rows per correlation. Both DBs: `PRAGMA integrity_check = ok`. Final evidence logs contain no `database is locked`, `Traceback`, `ERROR=`, or `poll error`. |
| E2 agent mode | No provider keys were configured, so the fan-out used the deterministic defense fallback. This is an outage/fallback path, not an LLM A/B result. | Live launcher output reported no `GROQ_API_KEY`; same as E1 `/api/health` fallback mode |

### Observed failure fixed during E2

The first N=5 run authorized custom targets for `e2-inj-4` (`esp32_temp_02`) and `e2-inj-5`
(`esp32_door_01`), but `run_injector` did not pass those targets into the anomaly helpers. The helpers
correctly rejected the mismatch (`expected attack_flood on 'esp32_temp_01', got ... esp32_temp_02`), so
only three injectors reached `mqtt_events` while all five appeared in `policy_audit`. The launcher now
forwards `device_id` and `topic` from the authorized spec, and
`test_scenario_helper_uses_authorized_custom_target` prevents regression. Both final runs above were
produced after this fix.

### E2 limits / not claimed

- `isolate_device` DENY rows (N=3: `5`, N=5: `13`) are the existing `5/60s` policy rate limit under
  simultaneous high-severity attacks. They are recorded policy decisions, not silent drops or bypasses.
- Some incident groups are `unattributed:<device>` when a detector alert has no attack correlation in
  the same poll. They are still fanned out, but they are not counted as attack-correlated evidence.
- `-StopAfterSeconds` remains a supervised verification control, not the documented operator path.
- No live LLM provider, A/B comparison, physical device, RF, CSI, PHY fingerprint, or SDR measurement
  was performed.

## Checkpoint 3-Extended — E3 Provider Adapter — ✅ IMPLEMENTED (mock-verified)

Additive to E1 and E2: the C1, C2, C3, E1, and E2 evidence above is unchanged. No live provider key
was configured at any point, so no LLM response was observed; everything below is verified from mocks
and local SQLite only.

| Item | Result | Evidence |
|------|--------|----------|
| E3 adapter | `src/agents/provider.py` centralizes provider selection, lazy client creation, request timeout, bounded retry, circuit breaker, call/cost budget, and response normalization for OpenAI-compatible SDKs and Anthropic messages. | `src/agents/provider.py`; `tests/test_provider_adapter.py` |
| E3 provider coverage | Profiles for OpenAI, Anthropic, Google AI Studio, OpenRouter, plus legacy Groq/DeepSeek. Keys are read only from env or an injected secret store; no key value is logged or persisted by the adapter. | `PROFILES` in `src/agents/provider.py`; no-key and explicit-provider tests |
| E3 agent refactor | `DefenseAgent` and `AttackAgent` now share the adapter; the existing `client=` injection path remains intact. SDK import failure, missing key, circuit-open, and exhausted budget all route to the deterministic fallback. | `src/agents/defense_agent.py`, `src/agents/attack_agent.py`; agent fallback tests |
| E3 per-incident evidence | Each incident gets an `llm_mode` timeline event with `mode`, `provider`, `model`, `circuit`, and error; attack results and `policy_audit.context_json` carry mode/provider/model. Dashboard `/api/health` exposes `providers.roles` next to the legacy `llm_mode` fields. | `tests/test_provider_adapter.py`; `src/dashboard/app.py`, `src/dashboard/static/index.html` |
| E3 A/B mechanism | `CERBERUS_LLM_AB_PROVIDERS` (or role-specific variant) selects two or more keyed providers; a stable `role:assignment_key` hash picks one per incident/attack. Assignment is deterministic and testable, but no comparison result exists without keys. | `resolve_provider`, `build_health_status`; A/B tests |
| E3 tests | Full suite green. | `& .\.venv\Scripts\python.exe -m pytest tests -q` -> `96 passed in 255.35s`; focused `tests/test_provider_adapter.py tests/test_agents.py` -> `21 passed in 1.38s` |

### E3 limits / not claimed

- No live request was sent to any provider. Default model IDs are placeholders and must be confirmed
  when real keys are available; they are not presented as verified working models.
- No A/B result, latency comparison, quality score, or cost figure is claimed. The spend cap is a
  bounded call budget plus an optional token-cost ceiling; no real token accounting was observed.
- Anthropic support is translated and mock-verified only; the live SDK path has not been exercised.
- Deterministic fallback remains the only agent mode in all E1/E2 evidence and in the current demo.
