# src/agents/

LLM-driven agents (Checkpoint 3, tasks C3-T04, C3-T05; extended in C3-E / E3).

Files:
- `provider.py` — provider-agnostic adapter (OpenAI, Anthropic, Google AI Studio,
  OpenRouter, legacy Groq/DeepSeek). Env-only keys, lazy client creation, timeout,
  bounded retry, circuit breaker, call/cost budget, normalized tool calls, and
  deterministic A/B assignment. No key value is logged or persisted.
- `defense_agent.py` — tool-calling investigation: receives each detection, gathers
  evidence via `tools/`, builds the incident timeline, recommends a response.
  The model proposes; the policy layer disposes.
- `attack_agent.py` — bounded attack proposals. Executes only through `PolicyGate`.
- `tools/` — deterministic server-side tools the agents may call
- `fallback.py` — deterministic rules-only behavior when APIs are down, rate-limited,
  circuit-broken, or unbudgeted (task C3-T09) — the loop must never crash on API failure

Every incident gets an `llm_mode` timeline event recording `mode`, `provider`,
`model`, `circuit`, and any error. Attack results and `policy_audit.context_json`
carry the same fields. With no configured key, `mode=fallback` is the only observed
mode; no live provider result has been verified.

Safety invariant (from the proposal): scope-locking + rate limiting on every
tool; no agent output is executed directly without a policy check.
