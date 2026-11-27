"""E3 provider adapter tests — all mocks, no network, no API keys."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from src.agents import (
    AttackAgent,
    DefenseAgent,
    ProviderAdapter,
    ProviderUnavailable,
    build_health_status,
    resolve_provider,
)
from src.policy import PolicyGate
from src.storage.db import open_db

_ENV_KEYS = (
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY",
    "OPENROUTER_API_KEY", "OLLAMA_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY",
    "CERBERUS_DEFENSE_PROVIDER", "CERBERUS_ATTACK_PROVIDER",
    "CERBERUS_LLM_AB_PROVIDERS", "CERBERUS_DEFENSE_AB_PROVIDERS",
    "CERBERUS_ATTACK_AB_PROVIDERS", "CERBERUS_LLM_MAX_ATTEMPTS",
    "CERBERUS_LLM_MAX_CALLS", "CERBERUS_LLM_MAX_ESTIMATED_USD",
    "CERBERUS_LLM_CIRCUIT_FAILURES", "CERBERUS_LLM_CIRCUIT_COOLDOWN_S",
    "CERBERUS_LLM_RETRY_BASE_S", "CERBERUS_LLM_RETRY_MAX_S",
    "CERBERUS_LLM_TIMEOUT_S", "CERBERUS_LLM_USD_PER_1K_TOKENS",
    "CERBERUS_LLM_MAX_TOKENS", "CERBERUS_OLLAMA_MODEL",
)


@pytest.fixture(autouse=True)
def clean_provider_env(monkeypatch):
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def _response(content="{}", tool_calls=None, usage=None):
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage)


class _Completions:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeOpenAIClient:
    def __init__(self, responses):
        self.completions = _Completions(responses)
        self.chat = SimpleNamespace(completions=self.completions)


class FakeAnthropicClient:
    def __init__(self, blocks):
        self.blocks = blocks
        self.calls: list[dict] = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(content=self.blocks, usage=SimpleNamespace(input_tokens=8, output_tokens=4))


def test_provider_selection_without_keys_uses_legacy_names(monkeypatch):
    assert resolve_provider("defense") == "groq"
    assert resolve_provider("attack") == "deepseek"
    health = build_health_status()
    assert health["roles"]["defense"]["mode"] == "fallback"
    assert health["roles"]["attack"]["mode"] == "fallback"
    assert health["ab"]["enabled"] is False


def test_provider_selection_priority_and_explicit_override(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "mock-only")
    assert resolve_provider("defense") == "anthropic"
    monkeypatch.setenv("CERBERUS_ATTACK_PROVIDER", "openrouter")
    assert resolve_provider("attack") == "openrouter"
    health = build_health_status()
    assert health["roles"]["attack"]["mode"] == "fallback"  # no OpenRouter key


def test_ab_assignment_is_stable_and_uses_both_providers(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "mock-openai")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "mock-anthropic")
    monkeypatch.setenv("CERBERUS_LLM_AB_PROVIDERS", "openai,anthropic")
    chosen = [resolve_provider("defense", assignment_key=f"incident-{i}") for i in range(40)]
    assert set(chosen) == {"openai", "anthropic"}
    assert resolve_provider("defense", assignment_key="incident-7") == chosen[7]
    assert build_health_status()["roles"]["defense"]["ab_providers"] == ["openai", "anthropic"]


def test_no_key_fails_closed_without_a_request():
    adapter = ProviderAdapter("defense")
    assert adapter.status().mode == "fallback"
    with pytest.raises(ProviderUnavailable):
        adapter.complete(messages=[{"role": "user", "content": "hi"}])
    assert adapter.calls == 0


def test_retry_succeeds_and_backoff_is_bounded():
    sleeps = []
    client = FakeOpenAIClient([RuntimeError("transient"), _response('{"ok": true}')])
    adapter = ProviderAdapter("defense", client=client, sleep=sleeps.append)
    result = adapter.complete(messages=[{"role": "user", "content": "hi"}])
    assert json.loads(result.content)["ok"] is True
    assert adapter.calls == 2
    assert sleeps == [0.25]
    assert adapter.status().circuit == "closed"
    assert adapter.status().last_error is None


def test_circuit_breaker_opens_and_blocks_further_requests(monkeypatch):
    monkeypatch.setenv("CERBERUS_LLM_CIRCUIT_FAILURES", "2")
    monkeypatch.setenv("CERBERUS_LLM_MAX_ATTEMPTS", "1")
    monkeypatch.setenv("CERBERUS_LLM_CIRCUIT_COOLDOWN_S", "60")
    client = FakeOpenAIClient([RuntimeError("boom"), RuntimeError("boom"), _response("{}")])
    adapter = ProviderAdapter("attack", client=client, sleep=lambda _: None)
    for _ in range(2):
        with pytest.raises(Exception):
            adapter.complete(messages=[{"role": "user", "content": "hi"}])
    assert adapter.status().circuit == "open"
    with pytest.raises(ProviderUnavailable, match="circuit open"):
        adapter.complete(messages=[{"role": "user", "content": "hi"}])
    assert len(client.completions.calls) == 2


def test_call_budget_is_an_enforced_spend_cap(monkeypatch):
    monkeypatch.setenv("CERBERUS_LLM_MAX_CALLS", "1")
    monkeypatch.setenv("CERBERUS_LLM_MAX_ATTEMPTS", "1")
    client = FakeOpenAIClient([_response("{}"), _response("{}")])
    adapter = ProviderAdapter("defense", client=client)
    adapter.complete(messages=[{"role": "user", "content": "one"}])
    with pytest.raises(ProviderUnavailable, match="budget exhausted"):
        adapter.complete(messages=[{"role": "user", "content": "two"}])
    assert len(client.completions.calls) == 1
    assert adapter.status().remaining_calls == 0


def test_timeout_is_passed_on_every_request():
    client = FakeOpenAIClient([_response("{}")])
    adapter = ProviderAdapter("defense", client=client)
    adapter.complete(messages=[{"role": "user", "content": "hi"}])
    assert client.completions.calls[0]["timeout"] == 20.0


def test_openai_tool_calls_are_normalised():
    call = SimpleNamespace(
        id="call_1",
        function=SimpleNamespace(name="query_device_events", arguments='{"device_id": "d1"}'),
    )
    client = FakeOpenAIClient([_response("", tool_calls=[call])])
    adapter = ProviderAdapter("defense", client=client)
    result = adapter.complete(
        messages=[{"role": "user", "content": "hi"}],
        tools=[{"type": "function", "function": {"name": "query_device_events"}}],
    )
    assert result.tool_calls == [
        {
            "id": "call_1",
            "type": "function",
            "function": {"name": "query_device_events", "arguments": '{"device_id": "d1"}'},
        }
    ]


def test_anthropic_messages_and_tool_use_are_translated():
    client = FakeAnthropicClient(
        [
            {"type": "text", "text": "ok"},
            {"type": "tool_use", "id": "tu_1", "name": "query_device_events", "input": {"device_id": "d1"}},
        ]
    )
    adapter = ProviderAdapter("defense", client=client, provider="anthropic")
    result = adapter.complete(
        messages=[
            {"role": "system", "content": "be brief"},
            {"role": "user", "content": "look"},
        ],
        tools=[{"type": "function", "function": {"name": "query_device_events", "parameters": {"type": "object"}}}],
    )
    kwargs = client.calls[0]
    assert kwargs["system"] == "be brief"
    assert kwargs["max_tokens"] == 1024
    assert kwargs["tools"][0]["input_schema"] == {"type": "object"}
    assert result.content == "ok"
    assert result.tool_calls[0]["function"]["name"] == "query_device_events"
    assert json.loads(result.tool_calls[0]["function"]["arguments"]) == {"device_id": "d1"}
    assert result.usage == {"input_tokens": 8, "output_tokens": 4}


def test_agent_records_llm_mode_and_provider_per_incident(tmp_path):
    conn = open_db(tmp_path / "mode_llm.db")
    try:
        client = FakeOpenAIClient([_response(json.dumps({"recommended_action": "log_alert", "summary": "ok"}))])
        result = DefenseAgent(conn, PolicyGate(conn=conn), client=client).investigate(
            {"device_id": "esp32_temp_01", "severity": "low"}
        )
        assert result.mode == "llm"
        assert result.provider == "injected"
        modes = [e for e in result.incident.timeline if e.kind == "llm_mode"]
        assert len(modes) == 1
        assert modes[0].details["mode"] == "llm"
        assert modes[0].details["provider"] == "injected"
        assert "mode=llm provider=injected" in modes[0].summary
    finally:
        conn.close()


def test_agent_records_fallback_mode_per_incident_without_a_key(tmp_path):
    conn = open_db(tmp_path / "mode_fb.db")
    try:
        result = DefenseAgent(conn, PolicyGate(conn=conn)).investigate(
            {"device_id": "esp32_temp_01", "severity": "low"}
        )
        assert result.mode == "fallback"
        assert result.provider == "groq"
        modes = [e for e in result.incident.timeline if e.kind == "llm_mode"]
        assert len(modes) == 1
        assert modes[0].details["mode"] == "fallback"
        assert modes[0].details["provider"] == "groq"
    finally:
        conn.close()


def test_agent_falls_back_when_budget_is_exhausted(tmp_path, monkeypatch):
    monkeypatch.setenv("CERBERUS_LLM_MAX_CALLS", "1")
    monkeypatch.setenv("CERBERUS_LLM_MAX_ATTEMPTS", "1")
    conn = open_db(tmp_path / "budget.db")
    try:
        agent = DefenseAgent(
            conn,
            PolicyGate(conn=conn),
            client=FakeOpenAIClient([_response('{"recommended_action": "log_alert"}'), _response("{}")]),
        )
        assert agent.investigate({"device_id": "esp32_temp_01", "severity": "low"}).mode == "llm"
        second = agent.investigate({"device_id": "esp32_temp_01", "severity": "low"})
        assert second.mode == "fallback"
        assert "budget exhausted" in (second.error or "")
    finally:
        conn.close()


def test_attack_result_records_provider_and_model(tmp_path):
    conn = open_db(tmp_path / "atk_mode.db")
    try:
        client = FakeOpenAIClient([_response(json.dumps({"action": "attack_flood", "target": "esp32_temp_01"}))])
        agent = AttackAgent(conn, PolicyGate(conn=conn), client=client, model="mock-model")
        result = agent.run_scenario(count=1, interval=0.0)
        assert result.mode == "llm"
        assert result.provider == "injected"
        assert result.model == "mock-model"
        assert result.plan["provider"] == "injected"
    finally:
        conn.close()


def test_ollama_profile_requires_no_secret_key():
    from src.agents.provider import PROFILES

    env = {
        "CERBERUS_DEFENSE_PROVIDER": "ollama",
        "CERBERUS_OLLAMA_MODEL": "qwen3-vl:4b-instruct",
    }
    assert resolve_provider("defense", env=env) == "ollama"
    assert PROFILES["ollama"].api_key({}) == "ollama"  # SDK placeholder, not a secret
    adapter = ProviderAdapter("defense", env=env)
    assert adapter.status().mode == "live"
    assert adapter.status().model == "qwen3-vl:4b-instruct"
    assert build_health_status(env=env)["roles"]["defense"]["provider"] == "ollama"


def test_ollama_local_live_smoke():
    """Opt-in real check: runs only when the local Ollama server is reachable."""
    import httpx

    try:
        httpx.get("http://127.0.0.1:11434/api/tags", timeout=2.0).raise_for_status()
    except Exception:
        pytest.skip("local Ollama server is not running")

    env = {
        "CERBERUS_DEFENSE_PROVIDER": "ollama",
        "CERBERUS_LLM_MAX_ATTEMPTS": "1",
        "CERBERUS_LLM_TIMEOUT_S": "120",
    }
    adapter = ProviderAdapter("defense", env=env)
    result = adapter.complete(
        messages=[
            {"role": "system", "content": "Reply with JSON only."},
            {"role": "user", "content": 'Return exactly {"ok": true}'},
        ],
        temperature=0.1,
    )
    assert "ok" in result.content
    assert result.provider == "ollama"
    assert result.usage and result.usage.get("total_tokens", 0) > 0

    tool_result = adapter.complete(
        messages=[{"role": "user", "content": "Inspect esp32_temp_01 with the available tool."}],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "query_device_events",
                    "description": "Fetch recent MQTT events for a device from SQLite.",
                    "parameters": {
                        "type": "object",
                        "properties": {"device_id": {"type": "string"}},
                        "required": ["device_id"],
                    },
                },
            }
        ],
        tool_choice="auto",
        temperature=0.1,
    )
    assert tool_result.tool_calls[0]["function"]["name"] == "query_device_events"
