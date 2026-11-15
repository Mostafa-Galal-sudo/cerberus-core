# src/agents/

LLM-driven agents (Checkpoint 3, tasks C3-T04, C3-T05).

Planned files:
- `defense_agent.py` — Groq API, tool-calling: receives each detection, gathers
  evidence via `tools/`, builds the incident timeline, recommends a response.
  The model proposes; the policy layer disposes.
- `attack_agent.py` — DeepSeek API: generates/adapts attacks (MQTT flood,
  injection, identity spoofing). Executes only through the policy layer.
- `tools/` — deterministic server-side tools the agents may call
- `fallback.py` — deterministic rules-only behavior when APIs are down or
  rate-limited (task C3-T09) — the loop must never crash on API failure

Safety invariant (from the proposal): scope-locking + rate limiting on every
tool; no agent output is executed directly without a policy check.
