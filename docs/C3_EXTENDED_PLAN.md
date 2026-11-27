# C3-Extended

**Status:** E1 and E2 implemented with live lab evidence; E3 implemented and mock-verified, with live keyed verification and the two-provider A/B comparison still blocked on credentials; E4–E7 remain proposed scope only. No dates or durations are attached.
**Relationship to C3:** extends the already-completed Checkpoint 3 without modifying or replacing its evidence.
**Mode:** simulation-only. Isolated lab traffic, no physical ESP32, no RF/CSI/SDR measurements, no external network targets.

## Implemented now

### E1 — Continuous simulated SOC — implemented

- `.\demo.ps1 -Live` starts the live stack; plain `.\demo.ps1` still runs the C3 three-cycle demo.
- Components: `src.live.subscriber` (sole writer of `mqtt_events`), `src.live.publisher`,
  `src.live.injector`, `src.live.worker`, and `src.live.summary`.
- Publisher and injector communicate through real local MQTT sockets; subscriber callbacks persist rows
  with UTC timestamps. Components emit UTC-prefixed logs.
- The worker fits a benign baseline, applies explicit live rules, and routes incidents through the
  existing `DefenseAgent -> PolicyGate` path. Missing-baseline devices do not receive deviation alerts.
- Dashboard APIs and SSE read the same live DB. Evidence numbers, DB paths, and observed failures are
  recorded in `docs/PROGRESS.md`.
- `-StopAfterSeconds` is a supervised stop control for verification runs; the documented operator path
  is `.\demo.ps1 -Live` stopped by the operator.

### E2 — Concurrent attacks with per-attack correlation — implemented

- `.\demo.ps1 -Live -ConcurrentInjectors <1..5>` starts dedicated injectors from
  `src.live.injector`. N=1 keeps the E1 path; N=3 and N=5 use `E2_SPECS` with distinct injector IDs,
  MQTT client IDs, lab targets, topics, and isolated `rate_key` buckets while the audit actor stays
  `attack`.
- Attack payloads carry `correlation_id` and `injector_id`. `src.live.subscriber` persists them in
  `mqtt_events`; `PolicyGate` records the same identifiers in `policy_audit.context_json`.
- `src.live.worker --fanout` groups detections by correlation ID and dispatches one separated
  incident chain per attack through `DefenseAgent -> PolicyGate`, with deduplication across polls.
- Aggregated evidence in `docs/PROGRESS.md` covers N=3 and N=5 runs: every audit correlation appears
  in MQTT events and incident detection evidence exactly once, with no SQLite lock errors and no
  integrity failures.

### E3 — Generic LLM provider adapter — implemented (mock-verified)

- `src/agents/provider.py` replaces the Groq/DeepSeek-only client paths with one bounded request path:
  lazy client creation, per-request timeout, bounded retry, circuit breaker, call/cost budget, and
  normalized responses for OpenAI-compatible SDKs and Anthropic messages.
- Provider profiles: OpenAI, Anthropic, Google AI Studio, OpenRouter, a local Ollama profile, plus
  legacy Groq and DeepSeek profiles so existing deployments keep their behaviour. Selection is via
  `CERBERUS_DEFENSE_PROVIDER` / `CERBERUS_ATTACK_PROVIDER`; keys are read only from environment or an
  injected secret store and are never logged. Ollama needs no secret — the SDK placeholder `ollama`
  is used — and is opt-in so existing fallback evidence stays reproducible.
- A/B assignment is deterministic: `CERBERUS_LLM_AB_PROVIDERS` (or a role-specific variant) names two
  or more keyed providers and `assignment_key` hashes to a stable choice per incident/attack. This is
  an experiment assignment mechanism, not a completed comparison.
- Every incident records an `llm_mode` timeline event with `mode`, `provider`, `model`, `circuit`, and
  any error; attack results and `policy_audit.context_json` carry the same mode/provider/model fields.
  The dashboard health endpoint exposes `providers.roles` alongside the legacy `llm_mode` fields.
- Deterministic fallback remains authoritative on missing keys, SDK import failure, circuit-open,
  budget exhaustion, or provider errors. No live provider response has been observed: all current
  agent evidence is fallback mode, not an LLM result.

## Goal

Turn the three-cycle demo into a continuously running simulated SOC, exercise several attacks at the same
time, remove single-provider LLM dependency, add protocols beyond MQTT, secure those protocols so the
attacks have real controls to hit, and capture the whole thing on a live local network.

## Protocols

| Protocol | Status | Why | Attack surface to exercise | Detection signals |
|----------|--------|-----|----------------------------|-------------------|
| MQTT | existing, extended | primary IoT bus already implemented | unauthorized publish, wildcard/topic-ACL escape, retained-message poisoning, client-id spoofing, QoS abuse, flood | topic entropy, publish rate, payload size, QoS distribution, unknown device id |
| HTTP / HTTPS | new (E4) | realistic telemetry + alerting path, easy to simulate in-process | credential stuffing, token replay, path traversal against a lab-only app, malformed JSON, request flood | status-code mix, auth-failure rate, request rate, URI entropy, body size |
| CoAP / UDP | new (E4) | constrained-device protocol, different transport from MQTT | spoofed endpoint, message replay, resource enumeration, amplification attempt | message type/code, duplicate message-id/token, option entropy, UDP rate |
| DNS | new (E4) | high-signal lateral/exfiltration behaviour | high-entropy labels, NXDOMAIN flood, fast-flux-like domain churn | label length/entropy, TXT share, NXDOMAIN rate, unique-domain churn |

**Not in this scope (stretch candidates only):** AMQP, Modbus TCP. They can be added later under the
same `protocol` column; they are not part of the C3-E acceptance.

**Security layers belong to E5, not E4:** TLS/mTLS on MQTT (8883) with per-device topic ACLs,
DTLS/PSK for CoAP, and auth/token/rate-limit on the lab HTTP endpoint. E4 establishes the parsers and
detectors; E5 adds controls for the attacks to target.

## Work items

| ID | Work | Deliverable / evidence to accept | Depends on |
|----|------|----------------------------------|------------|
| E1 | **implemented** — Continuous simulated demo: Mosquitto + `traffic_gen.py` as a detached publisher + anomaly injector + detection worker + FastAPI dashboard with SSE | long-running run stopped only by operator; MQTT publish over real sockets; DB updated from subscriber callback; UTC timestamps in logs; evidence in `docs/PROGRESS.md` | existing C3 |
| E2 | **implemented** — Concurrent attacks: N injectors with distinct client IDs and targets, correlation ID per attack, fan-out of every detection to the defense agent | N=3/5 runs with separated incidents, no DB corruption under the existing write lock, auditable per-attack chain; evidence in `docs/PROGRESS.md` | E1 |
| E3 | **implemented (mock-verified)** — LLM provider adapter replacing the Groq/DeepSeek-specific paths | key only in env/secret store; retry, timeout, circuit breaker, spend cap; `mode=llm/fallback` recorded per incident; A/B assignment mechanism ready. Live keyed verification and the actual two-provider comparison remain blocked on credentials. | existing C3 |
| E4 | HTTP, CoAP, DNS ingestion: `protocol` column, parsers, per-protocol features, rules, and fingerprint baselines | labelled events for each protocol, working detectors, no regression against the existing MQTT benchmark | E1 |
| E5 | Protocol security controls: MQTT TLS/mTLS + topic ACLs, CoAP DTLS/PSK, lab HTTP auth + rate limits | attack scenarios run against those controls in the isolated lab; ALLOW/DENY rows in `policy_audit`; PolicyGate remains the single response path | E4 |
| E6 | Live local network: `tshark`/`dumpcap` capture on loopback or an isolated LAN interface | pcap with UTC filenames plus metadata sheet; dashboard reading the same traffic being captured; no traffic aimed outside the lab | E1 |
| E7 | Adversarial adaptation: attack agent changes scenario after isolation | adaptation log and proof that the loop reopened on the same incident chain | E2, E3 |

**Order:** E1 → E2 → E3 → E6 → E4 → E5 → E7.

**Cut line if scope is reduced:** stop at E6 and move E4/E5 to the next checkpoint. Do not drop E2;
concurrency is the stress test that exposes DB and policy-gate weaknesses.

## LLM provider options for E3

Verified from official provider docs during the discussion (not provisioned, no keys held):

| Provider | Key location | Candidate models |
|----------|--------------|------------------|
| OpenAI | `platform.openai.com/api-keys` | `gpt-6.2-sol`, `gpt-6-luna`, `gpt-6.2-astra` |
| Anthropic | `console.anthropic.com` | `claude-sonnet-5-5`, `claude-haiku-5-5`, `claude-opus-5-5` |
| Google AI Studio | `aistudio.google.com/apikey` | `gemini-4-hydrogen`, `gemini-4-argon`, `gemini-3.8-flash` |
| OpenRouter | `openrouter.ai/keys` | single OpenAI-compatible endpoint for A/B across many models |
| Ollama (local) | no key — local HTTP endpoint `http://127.0.0.1:11434/v1` | locally installed model, currently `qwen3-vl:4b-instruct` |

Cyber-specific tiers (for example OpenAI Daybreak models) may require approved-access programmes;
do not assume availability. The deterministic fallback stays as an outage path, not as the default.

Adapter configuration (all optional; keys/models are resolved at call time, never baked into code):

| Variable | Purpose |
|----------|---------|
| `CERBERUS_DEFENSE_PROVIDER`, `CERBERUS_ATTACK_PROVIDER` | force a provider name for a role |
| `CERBERUS_<PROVIDER>_MODEL` | override the placeholder default model ID |
| `CERBERUS_LLM_AB_PROVIDERS` / `CERBERUS_<ROLE>_AB_PROVIDERS` | comma-separated A/B provider list |
| `CERBERUS_LLM_TIMEOUT_S`, `CERBERUS_LLM_MAX_ATTEMPTS`, `CERBERUS_LLM_RETRY_BASE_S`, `CERBERUS_LLM_RETRY_MAX_S` | request timeout and bounded retry |
| `CERBERUS_LLM_CIRCUIT_FAILURES`, `CERBERUS_LLM_CIRCUIT_COOLDOWN_S` | circuit breaker thresholds |
| `CERBERUS_LLM_MAX_CALLS`, `CERBERUS_LLM_MAX_ESTIMATED_USD`, `CERBERUS_LLM_USD_PER_1K_TOKENS` | call budget and optional token-cost ceiling |

Model IDs shipped as defaults are placeholders pending keyed verification; do not report them as
verified working models.

## Evidence discipline

Every added item needs a before/after baseline with numbers: detection F1/FPR, latency, policy DENY
count, and `mode=llm/fallback`. More components are not automatically a stronger result. Final phase
evidence: one entry in `docs/PROGRESS.md`, a `checkpoint-3-extended` tag, a run log containing publisher
count, concurrent attack count, active model, DENY count, and pcap identifier.

## Explicitly out of scope

- Physical ESP32 devices or firmware-on-hardware work.
- RF, CSI, PHY fingerprinting, or SDR measurement claims.
- Any attack aimed at a network or device outside the isolated lab.
- Rewriting or deleting the evidence already recorded for C1, C2, and C3.
