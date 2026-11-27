# CERBERUS — Autonomous Multi-Layer IoT Cyber Defense Platform

Graduation project — Faculty of Engineering, Electronics & Communications
Engineering, Damanhour University. Supervisor: Dr. Mai Shahin.

Simulation-only multi-layer IoT cyber defense demonstrator: simulated MQTT
telemetry, rules + ML + device fingerprint detection, LLM-driven attack/defense
agents with deterministic fallback, policy-bounded automated response, and a
SOC dashboard with SSE. No physical ESP32, RF, CSI, or SDR measurements are
claimed.

## Build status

| Checkpoint | Window | Scope | Status |
|---|---|---|---|
| C1 — Foundation & data pipeline | 16-22 Nov | simulator + storage + CICIoT2023 EDA | complete |
| C2 — Detection engine v1 + benchmark | 23-29 Nov | rules vs ML vs hybrid | complete |
| C3 — Agents + response + dashboard | 30 Nov - 6 Dec | closed loop on simulated traffic | complete (26 Nov) |
| C3-Extended E1 — Continuous simulated SOC | — | MQTT live stack + subscriber-owned DB + SSE dashboard | complete |
| C3-Extended E2 — Concurrent attacks | — | N=3/5 injectors, per-attack correlation, fan-out | complete |
| C3-Extended E3 — LLM provider adapter | — | OpenAI / Anthropic / Google / OpenRouter, retry + breaker + budget, fallback | complete (mock-verified; live keys pending) |
| C4 — Simulated testbed + lab dataset | 7-13 Dec | simulation-only scope; no physical hardware | not started |
| C5 — Closed loop on simulated testbed | 14-20 Dec | continuous demo + CIs | not started |
| C6 — Multi-protocol resilience (stretch) + final | 21-27 Dec | report only; no RF/SDR claims | not started |

## Repository layout

```
cerberus-core/
├── data/           datasets (git-ignored): raw / processed / lab
├── src/
│   ├── simulator/  simulated IoT traffic generation
│   ├── storage/    SQLite persistence layer
│   ├── detection/  rules + ML + fingerprinting + hybrid
│   ├── agents/     provider adapter + defense/attack agents + fallback
│   ├── policy/     single authorization gate (no bypass paths)
│   ├── live/       E1/E2 continuous MQTT stack (subscriber, publisher, injector, worker)
│   ├── response/   automated, policy-bounded isolation
│   ├── incidents/  incident schema + timeline
│   ├── dashboard/  SOC-style presentation layer
│   ├── capture/    testbed packet-capture pipeline
│   ├── attacks/    protocol + RF attack implementations
│   ├── evaluation/ benchmark harness + statistical evaluation
│   └── notebooks/  exploratory EDA notebooks
├── firmware/       ESP32 sketches (endpoints + attacker)
├── tests/          pytest suite
├── docs/           architecture, progress, case study, final report
└── results/        numeric experiment reports (Markdown)
```

Every folder has its own `README.md` describing its scope and planned files.

## Quick start

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
# install + start Mosquitto locally, then choose one launcher:
.\demo.ps1                              # C3: three closed-loop cycles
.\demo.ps1 -Live                        # E1: continuous simulated SOC, stop with Ctrl+C
.\demo.ps1 -Live -ConcurrentInjectors 3 # E2: three concurrent attacks
.\demo.ps1 -Live -ConcurrentInjectors 5 # E2: five concurrent attacks
```

`demo.ps1` is the only demo launcher. In `-Live` mode it checks the broker at
`127.0.0.1:1883`, creates a fresh `data/lab/live_traffic_<timestamp>.db`, then
starts:

1. `src.live.subscriber` — the only process that writes `mqtt_events`; retained
   messages are skipped so a fresh DB is not polluted by older runs.
2. `src.live.publisher` — benign MQTT seed plus continuous simulated traffic.
3. `src.live.injector` — policy-bounded flood/bloat/rogue attacks over MQTT only.
4. `src.live.worker` — baseline-fit + live rules, then `DefenseAgent -> PolicyGate`.
5. FastAPI dashboard + SSE on `http://127.0.0.1:8000`.

`-ConcurrentInjectors` keeps N=1 on the E1 path. Values 3 and 5 use `E2_SPECS`
with distinct MQTT client IDs, lab targets, topics, policy rate-limit buckets,
and a `correlation_id` per attack. The worker runs with `--fanout`, opening one
incident chain per correlated attack; `mqtt_events`, `policy_audit`, and
`incident_events` can be joined on that ID.

`.\demo.ps1 -Live -StopAfterSeconds <n>` is a supervised verification control;
it is not the normal operator path. Component logs are written to
`%TEMP%\cerberus_live_*.out.log`, and a one-line DB summary can be reproduced
with `python -m src.live.summary --db <path-to-live-db>`.

## LLM provider configuration (E3)

No key is required to run the demo: with no key the agents use deterministic fallback.
Keys belong in environment variables or a secret store, never in the repository.

```powershell
# choose a provider per role (legacy defaults: groq for defense, deepseek for attack)
$env:CERBERUS_DEFENSE_PROVIDER = "openai"      # openai | anthropic | google | openrouter | groq
$env:CERBERUS_ATTACK_PROVIDER  = "anthropic"
$env:OPENAI_API_KEY = "..."
$env:ANTHROPIC_API_KEY = "..."
```

Optional controls: `CERBERUS_<PROVIDER>_MODEL`, `CERBERUS_LLM_TIMEOUT_S`,
`CERBERUS_LLM_MAX_ATTEMPTS`, `CERBERUS_LLM_RETRY_BASE_S`,
`CERBERUS_LLM_CIRCUIT_FAILURES`, `CERBERUS_LLM_CIRCUIT_COOLDOWN_S`,
`CERBERUS_LLM_MAX_CALLS`, `CERBERUS_LLM_MAX_ESTIMATED_USD`,
`CERBERUS_LLM_USD_PER_1K_TOKENS`, and `CERBERUS_LLM_AB_PROVIDERS` for A/B
assignment. Every incident records an `llm_mode` event with the chosen mode,
provider, and model; `/api/health` reports `providers.roles` plus the legacy
`llm_mode` fields.

Default model IDs are placeholders. No live provider call or A/B comparison has
been performed, so no provider is claimed as verified working.

## Weekly plan and tasks

See `docs/CERBERUS_WEEKLY_CHECKPOINTS_TASKS.md` (53 tasks across 6 checkpoints,
critical path: C1-T05 -> C2-T07 -> C3-T08 -> C5-T01).

`demo.ps1` is the only demo launcher. It binds the dashboard to `127.0.0.1`,
uses `CERBERUS_PORT` if set (default 8000), and generates a
`CERBERUS_DASHBOARD_TOKEN` printed at startup. The release button asks for this
token once and caches it in `sessionStorage`.
