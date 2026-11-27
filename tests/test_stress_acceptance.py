"""Harsh acceptance tests: fault injection, secret hygiene, and bounded failure.

These tests deliberately break clients, responses, clocks, and budgets. The
required property is always the same: the loop must degrade to deterministic
fallback without leaking keys, without an uncaught exception, and without
exceeding the configured call budget.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from src.agents import (
    DefenseAgent,
    ProviderAdapter,
    ProviderRequestError,
    ProviderUnavailable,
    redact_secrets,
    resolve_provider,
)
from src.policy import PolicyGate
from src.storage.db import open_db

_SECRET = "leak-me-please-9931"


class _Completions:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def create(self, **_kwargs):
        self.calls += 1
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeClient:
    def __init__(self, responses):
        self.completions = _Completions(responses)
        self.chat = SimpleNamespace(completions=self.completions)


def _response(content="{}", tool_calls=None):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=tool_calls))],
        usage=SimpleNamespace(total_tokens=12),
    )


def _tool_call(name, arguments):
    return SimpleNamespace(
        id="call_x",
        function=SimpleNamespace(name=name, arguments=arguments),
    )


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in (
        "GROQ_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY", "OLLAMA_API_KEY",
        "CERBERUS_DEFENSE_PROVIDER", "CERBERUS_ATTACK_PROVIDER",
        "CERBERUS_LLM_AB_PROVIDERS", "CERBERUS_LLM_MAX_ATTEMPTS",
        "CERBERUS_LLM_MAX_CALLS", "CERBERUS_LLM_CIRCUIT_FAILURES",
        "CERBERUS_LLM_CIRCUIT_COOLDOWN_S", "CERBERUS_LLM_RETRY_BASE_S",
    ):
        monkeypatch.delenv(key, raising=False)


@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError("request timed out"),
        RuntimeError("429 rate limited"),
        RuntimeError("500 upstream failure"),
        ConnectionResetError("connection reset"),
        ValueError("provider returned garbage"),
    ],
)
def test_transient_failures_always_degrade_to_fallback(tmp_path, failure):
    conn = open_db(tmp_path / f"chaos_{type(failure).__name__}.db")
    try:
        client = FakeClient([failure, failure])
        gate = PolicyGate(conn=conn)
        result = DefenseAgent(conn, gate, client=client).investigate(
            {"device_id": "esp32_temp_01", "severity": "high", "explanation": "fault injection"}
        )
        assert result.mode == "fallback"
        assert result.error and str(failure) in result.error
        assert result.isolation is not None and result.isolation.executed is True
        assert client.completions.calls == 2  # one bounded retry, never a loop
        assert any(e.kind == "llm_mode" and e.details["mode"] == "fallback" for e in result.incident.timeline)
    finally:
        conn.close()


def test_empty_choices_and_non_object_payload_fall_back(tmp_path):
    conn = open_db(tmp_path / "malformed.db")
    try:
        empty = SimpleNamespace(choices=[])
        client = FakeClient([empty, empty])
        result = DefenseAgent(conn, PolicyGate(conn=conn), client=client).investigate(
            {"device_id": "esp32_temp_01", "severity": "high"}
        )
        assert result.mode == "fallback"
        assert "no choices" in (result.error or "")
    finally:
        conn.close()


def test_malformed_tool_arguments_do_not_break_the_loop(tmp_path):
    conn = open_db(tmp_path / "bad_args.db")
    try:
        client = FakeClient(
            [
                _response("", tool_calls=[_tool_call("query_device_events", "{not-json")]),
                _response(json.dumps({"recommended_action": "log_alert", "summary": "ok"})),
            ]
        )
        result = DefenseAgent(conn, PolicyGate(conn=conn), client=client).investigate(
            {"device_id": "esp32_temp_01", "severity": "low"}
        )
        assert result.mode == "fallback"  # bad tool args are a provider error path
        assert result.isolation is None
        assert client.completions.calls == 1  # fail fast, no retry on malformed tool output
    finally:
        conn.close()


def test_unknown_tool_is_reported_but_does_not_crash(tmp_path):
    conn = open_db(tmp_path / "unknown_tool.db")
    try:
        client = FakeClient(
            [
                _response("", tool_calls=[_tool_call("drop_database", "{}")]),
                _response(json.dumps({"recommended_action": "log_alert", "summary": "ok"})),
            ]
        )
        result = DefenseAgent(conn, PolicyGate(conn=conn), client=client).investigate(
            {"device_id": "esp32_temp_01", "severity": "low"}
        )
        assert result.mode == "llm"
        assert result.incident.reasoning_summary == "ok"
    finally:
        conn.close()


def test_circuit_half_open_allows_one_probe_then_blocks():
    now = [0.0]
    responses = [RuntimeError("boom"), RuntimeError("boom"), _response("{}"), _response("{}")]
    client = FakeClient(responses)
    env = {
        "CERBERUS_LLM_CIRCUIT_FAILURES": "2",
        "CERBERUS_LLM_CIRCUIT_COOLDOWN_S": "10",
        "CERBERUS_LLM_MAX_ATTEMPTS": "1",
        "CERBERUS_LLM_MAX_CALLS": "3",
    }
    adapter = ProviderAdapter("defense", env=env, client=client, sleep=lambda _: None, clock=lambda: now[0])
    for _ in range(2):
        with pytest.raises(ProviderRequestError):
            adapter.complete(messages=[{"role": "user", "content": "x"}])
    assert adapter.status().circuit == "open"
    with pytest.raises(ProviderUnavailable):
        adapter.complete(messages=[{"role": "user", "content": "x"}])

    now[0] = 11.0
    assert adapter.status().circuit == "half-open"
    assert adapter.complete(messages=[{"role": "user", "content": "probe"}]).content == "{}"
    assert adapter.status().circuit == "closed"
    with pytest.raises(ProviderUnavailable, match="budget exhausted"):
        # the breaker recovered, but the call budget is still enforced after recovery
        adapter.complete(messages=[{"role": "user", "content": "x"}])


def test_budget_is_exact_and_never_exceeded():
    env = {"CERBERUS_LLM_MAX_CALLS": "3", "CERBERUS_LLM_MAX_ATTEMPTS": "1"}
    client = FakeClient([_response("{}"), _response("{}"), _response("{}"), _response("{}")])
    adapter = ProviderAdapter("attack", env=env, client=client)
    for _ in range(3):
        adapter.complete(messages=[{"role": "user", "content": "x"}])
    assert client.completions.calls == 3
    with pytest.raises(ProviderUnavailable, match="budget exhausted"):
        adapter.complete(messages=[{"role": "user", "content": "x"}])
    assert client.completions.calls == 3


def test_keys_are_redacted_from_every_error_surface(monkeypatch, tmp_path):
    monkeypatch.setenv("GROQ_API_KEY", _SECRET)
    conn = open_db(tmp_path / "secret.db")
    try:
        client = FakeClient([RuntimeError(f"failed with {_SECRET}"), RuntimeError(f"failed with {_SECRET}")])
        agent = DefenseAgent(conn, PolicyGate(conn=conn), client=client)
        result = agent.investigate({"device_id": "esp32_temp_01", "severity": "high"})
        assert result.mode == "fallback"
        surfaces = [
            result.error or "",
            str(agent.adapter.status().to_dict()),
            " ".join(e.summary + json.dumps(e.details) for e in result.incident.timeline),
        ]
        assert all(_SECRET not in surface for surface in surfaces)
        assert "[REDACTED]" in (result.error or "")
        assert redact_secrets(f"key={_SECRET}") == "key=[REDACTED]"
    finally:
        conn.close()


def test_benchmark_log_redacts_dashboard_token():
    from src.evaluation.stress_benchmark import sanitise_log

    raw = "Release token (X-Cerberus-Token): abcDEF123+/==\n[worker] ready"
    cleaned = sanitise_log(raw)
    assert "abcDEF123+/==" not in cleaned
    assert "[REDACTED]" in cleaned
    assert "[worker] ready" in cleaned


def test_ab_assignment_is_stable_over_many_keys(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "mock-openai")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "mock-anthropic")
    monkeypatch.setenv("CERBERUS_LLM_AB_PROVIDERS", "openai,anthropic")
    seen = [resolve_provider("defense", assignment_key=f"inc-{i}") for i in range(1000)]
    assert set(seen) == {"openai", "anthropic"}
    assert seen[::137] == [resolve_provider("defense", assignment_key=f"inc-{i}") for i in range(0, 1000, 137)]
    assert len(set(seen[:100])) >= 2
