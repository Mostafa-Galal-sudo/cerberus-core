# CERBERUS — Autonomous Multi-Layer IoT Cyber Defense Platform

Graduation project — Faculty of Engineering, Electronics & Communications
Engineering, Damanhour University. Supervisor: Dr. Mai Shahin.

Multi-layer (RF + protocol) intrusion detection, LLM-driven attack/defense
agents, policy-bounded automated response, and RF-resilience measurement on an
ESP32-based IoT testbed.

## Build status

| Checkpoint | Window | Scope | Status |
|---|---|---|---|
| C1 — Foundation & data pipeline | 16-22 Nov | simulator + storage + CICIoT2023 EDA | complete |
| C2 — Detection engine v1 + benchmark | 23-29 Nov | rules vs ML vs hybrid | complete |
| C3 — Agents + response + dashboard | 30 Nov - 6 Dec | closed loop on simulated traffic | not started |
| C4 — Real testbed + lab dataset | 7-13 Dec | ESP32 + AP + gap report | not started |
| C5 — Closed loop on real testbed | 14-20 Dec | live demo + CIs | not started |
| C6 — RF resilience (stretch) + final | 21-27 Dec | NRF24L01 or fallback + report | not started |

## Repository layout

```
cerberus-core/
├── data/           datasets (git-ignored): raw / processed / lab
├── src/
│   ├── simulator/  simulated IoT traffic generation
│   ├── storage/    SQLite persistence layer
│   ├── detection/  rules + ML + fingerprinting + hybrid
│   ├── agents/     defense (Groq) + attack (DeepSeek) agents
│   ├── policy/     single authorization gate (no bypass paths)
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
# install + start Mosquitto locally, then:
python -m src.simulator.traffic_gen
```

## Weekly plan and tasks

See `../CERBERUS_WEEKLY_CHECKPOINTS_TASKS.md` (34 tasks across 6 checkpoints,
critical path: C1-T05 -> C2-T07 -> C3-T08 -> C5-T01).
