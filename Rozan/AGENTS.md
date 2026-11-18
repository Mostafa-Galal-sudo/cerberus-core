# AGENTS.md — CERBERUS

Hardware-software platform for multi-layer intrusion detection, automated policy-bounded response, and RF-resilience testing in Wi-Fi/MQTT IoT networks.

> **Repo layout note:** this codebase lives inside the `Rozan/` directory of the `cerberus-core` repository. Run every command below from `Rozan/`, not the repo root.

## Implementation plan

- **The plan lives in `docs/PLAN.md`.** Read it before doing any work. When you complete, replan, or re-scope work, update it — it is the source of truth for phase status, not this file.
- **Software first:** hardware delays must never block software deliverables. Phase 1 (software core) is the immediate priority; Phases 2–3 (testbed, RF resilience) come after. If hardware isn't available, build against the `CICIoT2023` dataset and simulated traffic instead.

## Architecture (five-layer closed loop)

Attack → Detection → Defense Agent → Response → Presentation. Respect these module boundaries; keep layers decoupled:

| Module | Responsibility |
|---|---|
| `agents/` | LLM agents via tool-calling scaffolds: DeepSeek = attack agent, Groq = defense agent |
| `detection/` | Hybrid IDS: unsupervised ML (Isolation Forest / Autoencoder, scikit-learn) + deterministic rules + device fingerprinting, with SHAP/LIME explainability |
| `gateway/` | MQTT telemetry, PCAP capture, automated endpoint isolation (Linux gateway) |
| `backend/` | Flask REST API + SQLite (devices, alerts, incident timelines, audit logs) |
| `frontend/` | Vanilla HTML/CSS/JS SOC dashboard (no JS frameworks) |
| `firmware/` | ESP-IDF C/C++ for ESP32 (`esp_wifi_80211_tx()` for frame injection) + NRF24L01 radio firmware — Phases 2–3 only |

Non-obvious rules:

- **Explainability is a requirement, not a feature.** Every detection alert must ship with SHAP/LIME-backed confidence calibration. No black-box detections.
- **Router agnosticism:** never add a dependency on OpenWrt or custom router firmware. All capture, attack injection, and isolation runs on the ESP32 nodes and the Linux gateway (Raspberry Pi or mini PC).
- **Agent guardrails are mandatory.** Both LLM agents act only through structured function-calling with (a) strict scope-locking — they must never target protected infrastructure (the gateway, broker control, SOC server) — and (b) rate limiting. Do not let agents call arbitrary network actions outside the scaffold.

## Stack & environment

- Python 3.12 (64-bit, via `py -3.12`). **Do not use the system `python`** — it is Python 3.14 **32-bit**, which has no prebuilt wheels for scipy/scikit-learn/shap and fails to build them from source.
- Create the venv with: `py -3.12 -m venv .venv`; run everything through `.venv\Scripts\python.exe`.
- Secrets via `.env` (copy from `.env.example`): `DEEPSEEK_API_KEY`, `GROQ_API_KEY`, `TELEGRAM_BOT_TOKEN`. Never hardcode keys; never commit `.env`.
- Mosquitto is the MQTT broker; PCAP tooling for packet capture; Telegram Bot API + webhooks for alerting.
- Firmware toolchain: ESP-IDF (not Arduino), Phases 2–3.
- No Poetry/conda. Verification (from repo root):
  ```powershell
  .venv\Scripts\ruff.exe check .
  .venv\Scripts\python.exe -m pytest tests -q
  .venv\Scripts\python.exe -m backend.app   # Flask dev server on 127.0.0.1:5000, GET /health
  # ^ run as a module: `python backend\app.py` fails — sys.path[0] is backend/, so `import config` breaks.
  # DB selection: set DB_PATH env var (default cerberus.db; demo.db = seeded demo data).
  ```

## Safety & compliance

- All RF/attack testing runs inside a physically shielded enclosure per NTRA RF regulations. Never generate attack traffic (deauth, jamming, rogue AP) against networks outside the lab testbed.
- Automated isolation actions must stay policy-bounded: only endpoints confirmed by the defense agent, never blanket responses.
