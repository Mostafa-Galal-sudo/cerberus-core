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
- E2 concurrent attacks, E3 provider adapter, E4 multi-protocol ingestion, E5 protocol controls, E6 capture, and E7 adaptation remain unimplemented.
