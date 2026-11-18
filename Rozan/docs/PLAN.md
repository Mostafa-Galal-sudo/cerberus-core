# CERBERUS — Implementation Plan

> Source of truth for build status. Update this file as work completes, replans, or re-scopes. See `AGENTS.md` for architecture and constraints.

## Phase 1 — Software Core (immediate priority)

Full software stack validated against the public `CICIoT2023` dataset and simulated traffic. Hardware not required.

- [x] Project scaffolding: package layout (`agents/`, `detection/`, `gateway/`, `backend/`, `frontend/`), `requirements.txt`, `.env.example`, venv setup *(done: Python 3.12 64-bit venv, deps installed, ruff + pytest passing, Flask `/health` live)*
- [x] Dataset pipeline: load + preprocess `CICIoT2023`, simulated MQTT/802.11 traffic generator — *done: `detection/schema.py` (canonical feature schema + label taxonomy), `detection/data.py` (chunked CSV loader), `detection/simulator.py` (scenario generator); 34 tests passing. Real CICIoT2023 CSVs not yet downloaded — place them in `data/` (git-ignored). Sources: official unb.ca/cic/datasets/iotdataset-2023.html; small preprocessed variant: HuggingFace `lacg030175/CIC-IoT-2023` (~1.3M rows, ~15% benign).*
- [x] Hybrid detection engine: rule-based thresholds, Isolation Forest / Autoencoder anomaly models, device behavioral fingerprinting — *done: `detection/rules.py` (7 explainable rules), `detection/ml_detector.py` (IF + MLP autoencoder, benign-quantile calibration), `detection/fingerprint.py` (per-device baselines + new-device flagging), `detection/engine.py` (weighted fusion ml 0.5 / rules 0.35 / fingerprint 0.15, threshold 0.5). 57 tests passing. Thresholds calibrated on simulated data so far — re-validate on real CICIoT2023 once CSVs are in `data/`.*
- [x] Explainability layer: SHAP/LIME integration, confidence-calibrated alert output — *done: `detection/explain.py` — SHAP TreeExplainer (exact on the IF, primary), LIME local surrogate (cross-check; runs in standardized space with `sample_around_instance=True`), `annotate_alerts()` merges ML attributions with rule/fingerprint reasons into the alert record. Fused score = alert confidence. LIME caveat: IF decision function is piecewise-constant, so LIME's local attributions are noisy — SHAP is authoritative.*
- [x] Attack agent: DeepSeek tool-calling scaffold, multi-layer attack generation (deauth, rogue AP, jamming; MQTT flooding, injection, spoofing) with scope-locking + rate limiting — *done: `agents/scaffold.py` (shared `LLMAgent` OpenAI-SDK-shaped tool-calling loop, `ScopePolicy` protected-infrastructure lock, `RateLimiter` injectable-clock, guardrail denials returned to the LLM as error tool-results), `agents/attack.py` (DeepSeek `deepseek-chat` via https://api.deepseek.com; tools: `list_attack_types`, `deploy_attack` — simulates traffic in the CICIoT2023 schema, scores through the engine, ingests + audits; `get_network_state`; deploy rate-limited 10/min, protected targets untouchable). Client injectable — tests use scripted fakes, no real API.*
- [x] Defense agent: Groq tool-calling scaffold, cross-layer correlation, incident timeline building, remediation decisioning with guardrails — *done: `agents/defense.py` (Groq `llama-3.3-70b-versatile` via https://api.groq.com/openai/v1; tools: `get_alert_details`, `list_open_alerts`, `correlate_alerts` (device×class clustering), `create_incident`, `append_timeline_event`, `request_isolation` — routes through the response policy, never touches device state directly; 5 isolations/min cap).*
- [x] Response layer: policy-bounded automated isolation of confirmed malicious endpoints — *done: `agents/response.py` (`ResponsePolicy`: protected devices, min-confidence 0.5, max 5 isolations/hour window, registry-only targets; `execute_isolation` = validate → set isolated → audit → timeline event; `release_device` manual-only operator action). End-to-end scripted-LLM test proves scaffold → defense tool → isolation lands in DB.*
- [x] Backend: Flask REST API + SQLite persistence (devices, alerts, timelines, audit logs) — *done: `backend/db.py` (plain sqlite3, WAL, JSON columns: alerts/devices/incidents+events/audit), `backend/app.py` (REST: alerts CRUD+status, devices+status, incidents+timeline, audit; POST alerts upserts device last_seen), `backend/ingest.py` (engine output → DB records with full feature snapshot). 81 tests incl. end-to-end engine→SHAP→DB→API.*
- [x] SOC dashboard: real-time device status, live alerts, explainability metrics, investigation reports — *done: `frontend/` (vanilla HTML/CSS/JS, dark SOC theme, 5s polling), served by Flask at `/`; shows stats row, filterable alert table, per-device status with isolate action, alert detail with score bars + SHAP attribution + rule reasons, incident timelines. `scripts/seed_demo.py` seeds a local demo DB. Visually verified in-browser.*
- [x] Alerting: Telegram bot + webhook push, structured audit logs — *done: `backend/alerting.py` (TelegramNotifier with rate limiting, WebhookNotifier for comma-separated `WEBHOOK_URLS`, AlertDispatcher fanout, `format_alert_message` with explanation; never raises into the pipeline; network calls mocked in tests), audit log was built with the backend. Set `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` in `.env` to enable live push.*

## Phase 2 — Physical Testbed Integration

- [ ] Flash ESP32 firmware (ESP-IDF), wire MQTT telemetry through Mosquitto on the gateway
- [ ] Execute controlled real-world protocol + RF attacks on the lab testbed
- [ ] Re-validate detection accuracy on lab-collected traffic; report with confidence intervals alongside CICIoT2023 benchmarks

## Phase 3 — RF Resilience Testing (stretch goal)

- [ ] Integrate NRF24L01 modules inside the shielded enclosure
- [ ] Measure detection accuracy / false-alarm degradation under controlled 2.4 GHz interference

## Hardware inventory (Phases 2–3)

- 4–5 ESP32 boards (IoT endpoints + 802.11 frame injection via `esp_wifi_80211_tx()`)
- Standard Wi-Fi AP/router (no OpenWrt/custom firmware dependency)
- Raspberry Pi or mini PC as Linux gateway
- NRF24L01 2.4 GHz radios, physically shielded enclosure (NTRA RF compliant)
