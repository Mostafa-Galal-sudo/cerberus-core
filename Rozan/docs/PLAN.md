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

## Related work & positioning (Nageshwaran & Ezekiel 2026)

Primary anchor: Nageshwaran, V.; Ezekiel, S. *Agentic AI and Large Language Models for Autonomous IoT Cybersecurity: A Systematic Survey, Taxonomy, and Research Roadmap.* Electronics **2026**, 15(12), 2740. https://doi.org/10.3390/electronics15122740 (PRISMA 2020, 153 studies 2020–2026, four-pillar taxonomy, companion kit DOI 10.5281/zenodo.20726552). Study map: `docs/2026-11-19_cerberus-study-map.pdf`.

### Where CERBERUS sits in the taxonomy

| Paper claim | Location | CERBERUS position |
|---|---|---|
| Hybrid line-rate ML + LLM reasoning for ambiguous cases is the most production-realistic pattern | §5.1.3 | Same: deterministic hybrid engine decides fast; LLM agents only investigate escalated alerts |
| 93% of surveyed IoT-IDS work is detection-only; response orchestration is the least mature and riskiest layer | §5.3.2 | In the remaining 7%: policy-bounded isolation + audit trail + incident timelines |
| Conventional detectors flag anomalies but cannot say *why*; LLM+XAI closes the gap | §6.1 | SHAP authoritative + LIME cross-check + rule reasons on every alert |
| CICIoT2023 is the de facto benchmark (33 attacks / 7 families) | §7.1 | Same dataset and 48-feature schema; simulated traffic shares the schema |

### Required evaluation additions (blocking for any paper submission)

1. **Cross-dataset transfer** — train on CICIoT2023, test on Edge-IIoTset and vice versa; report the 10–20 pp degradation that §7.1 documents rather than hiding it.
2. **Decision latency** — p50/p95/p99 per decision, including tool calls (ReAct 3-step loops are ~4× a single classification, §8.5).
3. **Prompt-injection robustness** — measured success rate over ≥25 injection patterns (reuse the kit's `sanitize.py` corpus, §8.2; base refs [94], [110]).
4. **Cost per decision** — tokens/USD per alert, logged from provider responses.
5. **Multi-turn adversarial harness** — quantify error propagation, context poisoning, and tool-use amplification; only 5/153 studies report any compound failure mode, so this is a publishable gap.

### Hardening work derived from the survey

- [ ] Add `sanitize` + untrusted-data framing to every tool result before it enters the LLM context (`agents/scaffold.py`) — network payloads are attacker-controlled text.
- [ ] Keep tool allow-lists and inter-agent boundaries explicit; document them as the layered defense §8.2 recommends.
- [ ] Add a human-approval gate for tier-1/tier-2 (critical) devices on top of the existing confidence, protected-device, and rate-limit gates.
- [ ] Add a `Research prototype — not for production. Human approval required for consequential actions.` notice to `README.md`.
- [ ] Map the audit log to the NIST AI RMF cycle (Govern–Map–Measure–Manage).

### Governance note

The survey uses autonomous quarantine as its worked example of a **high-risk AI system** under the EU AI Act (Annex III) when applied to critical/medical devices, versus limited-risk for detection-only alerting. CERBERUS performs automated isolation, so the documentation must state the risk class, the human-oversight design, and the audit/explainability controls. Frameworks: NIST AI RMF 1.0 (AI 100-1, 2023) and Regulation (EU) 2024/1689.

### Residual risks to track

| Risk | Mitigation status |
|---|---|
| Indirect prompt injection via packet/log content | Partial — scope lock + tool allow-list; sanitization pending |
| Compound failure modes in multi-step loops | Not measured — harness pending |
| Single-dataset overfitting | Not measured — transfer study pending |
| Unfaithful LLM narration vs. actual attribution | Mitigated for detection (SHAP is authoritative); agent narration still free-form |
| Regulatory exposure of autonomous isolation | Partial — policy gates + audit; risk-class documentation pending |

### Key references

- **[45]** Neto et al., *CICIoT2023*, Sensors 2023 — dataset
- **[89]** Yao et al., *ReAct*, ICLR 2023 — tool-calling loop
- **[22]** Chhabra et al., *Agentic AI Security*, IEEE Access 2025 — threat/defense/evaluation map
- **[28]** Ismail et al., *SOAR-LLM*, Information 2025 — closest response-layer precedent
- **[57]/[58]** Fatema et al. (Federated XAI IDS) / Hermosilla et al. (SHAP vs LIME) — explainability
- **[94]/[110]** Greshake et al. / Liu et al. — prompt injection threat + benchmark
- **[112]** Arp et al., *Dos and Don'ts of ML in Computer Security*, USENIX Sec 2022 — evaluation discipline
- **[97]/[98]** NIST AI RMF 1.0 / EU AI Act 2024/1689 — governance
