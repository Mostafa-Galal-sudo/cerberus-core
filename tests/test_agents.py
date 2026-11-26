from __future__ import annotations

import json
import sys
from types import SimpleNamespace

from src.agents import AttackAgent, DefenseAgent
from src.incidents import IncidentStore
from src.policy import PolicyGate, RateLimiter
from src.response import IsolationRegistry
from src.storage.db import open_db, save_event


def _seed(conn):
    for sec in ("00", "20", "40"):
        save_event(
            conn,
            {
                "ts_utc": f"2026-11-26T10:00:{sec}.000+00:00",
                "device_id": "esp32_temp_01",
                "device_type": "climate",
                "topic": "lab/room1/climate",
                "qos": 0,
                "payload_size": 180,
                "payload_preview": '{"temp": 22.1}',
                "direction": "publish",
            },
        )


def test_defense_agent_fallback_when_no_api_key(monkeypatch, tmp_path):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    conn = open_db(tmp_path / "fb_def.db")
    try:
        _seed(conn)
        gate = PolicyGate(conn=conn)
        agent = DefenseAgent(conn, gate)

        res = agent.investigate(
            {"device_id": "esp32_temp_01", "severity": "high", "explanation": "rate_spike"}
        )
        assert res.mode == "fallback"
        assert res.isolation is not None and res.isolation.executed is True
        assert IsolationRegistry(conn).is_isolated("esp32_temp_01") is True
    finally:
        conn.close()


def test_defense_agent_llm_tool_calling_and_policy_isolation(tmp_path):
    conn = open_db(tmp_path / "llm_def.db")
    try:
        _seed(conn)

        tool_call = SimpleNamespace(
            id="call_1",
            function=SimpleNamespace(
                name="query_device_events",
                arguments=json.dumps({"device_id": "esp32_temp_01", "limit": 5}),
            ),
        )
        responses = [
            SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="", tool_calls=[tool_call]))]),
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(
                            content=json.dumps(
                                {
                                    "recommended_action": "isolate_device",
                                    "severity": "critical",
                                    "summary": "Confirmed flood via tool inspection",
                                }
                            ),
                            tool_calls=[],
                        )
                    )
                ]
            ),
        ]

        class FakeGroq:
            class chat:
                class completions:
                    @staticmethod
                    def create(**kwargs):
                        return responses.pop(0)

        gate = PolicyGate(conn=conn)
        incidents = IncidentStore(conn)
        agent = DefenseAgent(conn, gate, incidents=incidents, client=FakeGroq())
        res = agent.investigate({"device_id": "esp32_temp_01", "severity": "high"})

        assert res.mode == "llm"
        assert res.incident.severity == "critical"
        assert res.isolation is not None and res.isolation.executed is True
        assert [e.kind for e in res.incident.timeline] == ["detection", "tool_call", "isolation"]
    finally:
        conn.close()


def test_defense_agent_falls_back_on_api_exception(tmp_path):
    conn = open_db(tmp_path / "err_def.db")
    try:
        _seed(conn)

        class BrokenGroq:
            class chat:
                class completions:
                    @staticmethod
                    def create(**kwargs):
                        raise RuntimeError("429 rate limited")

        gate = PolicyGate(conn=conn)
        agent = DefenseAgent(conn, gate, client=BrokenGroq())
        res = agent.investigate({"device_id": "esp32_temp_01", "severity": "high"})

        assert res.mode == "fallback"
        assert res.error is not None and "429" in res.error
        assert IsolationRegistry(conn).is_isolated("esp32_temp_01") is True
    finally:
        conn.close()


def test_attack_agent_respects_policy_gate_and_injects_in_lab_scope(tmp_path):
    conn = open_db(tmp_path / "atk.db")
    try:
        class FakeDeepSeek:
            def __init__(self, payload):
                self._payload = payload

            @property
            def chat(self):
                payload = self._payload

                class _C:
                    class completions:
                        @staticmethod
                        def create(**kwargs):
                            return SimpleNamespace(
                                choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(payload)))]
                            )

                return _C()

        gate = PolicyGate(conn=conn)

        # Out-of-scope target proposed by LLM must be blocked by PolicyGate
        bad_agent = AttackAgent(
            conn,
            gate,
            client=FakeDeepSeek({"action": "attack_flood", "target": "*", "topic": "prod/x"}),
        )
        denied = bad_agent.run_scenario(count=3, interval=0.0)
        assert denied.executed is False
        assert denied.decision.allowed is False
        assert denied.events_injected == 0

        # Valid lab target executes through simulator/anomalies.py
        good_agent = AttackAgent(
            conn,
            gate,
            client=FakeDeepSeek(
                {"action": "attack_flood", "target": "esp32_temp_01", "topic": "lab/room1/climate"}
            ),
        )
        ok = good_agent.run_scenario(count=4, interval=0.0)
        assert ok.mode == "llm"
        assert ok.executed is True
        assert ok.events_injected == 4
    finally:
        conn.close()


def test_defense_agent_falls_back_on_sdk_import_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("GROQ_API_KEY", "broken-key")
    monkeypatch.setitem(sys.modules, "groq", None)
    conn = open_db(tmp_path / "sdk_def.db")
    try:
        _seed(conn)
        res = DefenseAgent(conn, PolicyGate(conn=conn)).investigate(
            {"device_id": "esp32_temp_01", "severity": "high"}
        )
        assert res.mode == "fallback"
        assert res.error
    finally:
        conn.close()


def test_attack_agent_falls_back_on_sdk_import_failure(monkeypatch, tmp_path):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "broken-key")
    monkeypatch.setitem(sys.modules, "openai", None)
    conn = open_db(tmp_path / "sdk_atk.db")
    try:
        mode, _plan, err = AttackAgent(conn, PolicyGate(conn=conn)).propose()
        assert mode == "fallback"
        assert err
    finally:
        conn.close()


def test_log_alert_denial_is_not_recorded_as_logged(monkeypatch, tmp_path):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    conn = open_db(tmp_path / "alert_deny.db")
    try:
        _seed(conn)
        gate = PolicyGate(conn=conn, ratelimiter=RateLimiter(limits={"log_alert": (0, 60.0)}))
        res = DefenseAgent(conn, gate).investigate(
            {"device_id": "esp32_temp_01", "severity": "low", "explanation": "low severity"}
        )
        assert res.mode == "fallback"
        assert "policy_denied" in [e.kind for e in res.incident.timeline]
        assert res.incident.outcome != "logged"
    finally:
        conn.close()
