"""Tests for the agent scaffold, attack/defense agents, and response policy.

All LLM clients are scripted fakes shaped like the OpenAI SDK — no network.
"""
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.attack import AttackTools, build_attack_agent, build_attack_tools
from agents.defense import DefenseTools, build_defense_agent
from agents.response import (
    IsolationDenied,
    ResponsePolicy,
    execute_isolation,
    release_device,
)
from agents.scaffold import (
    AgentLoopError,
    LLMAgent,
    RateLimiter,
    RateLimitExceeded,
    ScopePolicy,
    ScopeViolation,
    ToolSpec,
)
from backend.db import Database


# -- OpenAI-SDK-shaped fakes ---------------------------------------------------
@dataclass
class FakeFunction:
    name: str
    arguments: str


@dataclass
class FakeToolCall:
    id: str
    function: FakeFunction


@dataclass
class FakeMessage:
    content: str | None = None
    tool_calls: list | None = None


@dataclass
class FakeChoice:
    message: FakeMessage


@dataclass
class FakeResponse:
    choices: list


class ScriptedClient:
    """Returns scripted responses in order; records create() kwargs."""

    def __init__(self, responses: list):
        self._responses = list(responses)
        self.calls: list[dict] = []
        self.chat = SimpleNamespace(
            completions=SimpleNamespace(create=self._create),
        )

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


def tool_call(call_id: str, name: str, **args) -> FakeToolCall:
    return FakeToolCall(call_id, FakeFunction(name, json.dumps(args)))


# -- scaffold: rate limiter & scope --------------------------------------------
class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_rate_limiter_min_interval():
    clock = FakeClock()
    limiter = RateLimiter(min_interval=5.0, clock=clock)
    limiter.acquire()
    clock.now += 4.9
    with pytest.raises(RateLimitExceeded):
        limiter.acquire()
    clock.now += 0.2
    limiter.acquire()  # past the interval -> ok


def test_rate_limiter_window_budget():
    clock = FakeClock()
    limiter = RateLimiter(max_per_window=3, window_seconds=60.0, clock=clock)
    for _ in range(3):
        limiter.acquire()
    with pytest.raises(RateLimitExceeded):
        limiter.acquire()
    clock.now += 61.0
    limiter.acquire()  # window expired -> slot freed


def test_scope_policy_blocks_protected_substrings():
    policy = ScopePolicy()
    policy.check("cam-1")
    policy.check("CAM-1")  # case-insensitive
    for bad in ("mqtt-gateway", "the-broker-1", "soc-server"):
        with pytest.raises(ScopeViolation):
            policy.check(bad)


# -- scaffold: tool-calling loop -------------------------------------------------
def make_tool(handler, **spec_kwargs) -> ToolSpec:
    return ToolSpec(
        name="probe",
        description="probe tool",
        parameters={"type": "object", "properties": {}},
        handler=handler,
        **spec_kwargs,
    )


def test_agent_runs_tool_then_answers():
    seen = {}

    def handler(**kwargs):
        seen.update(kwargs)
        return {"echo": kwargs.get("value")}

    tool = make_tool(handler)
    client = ScriptedClient([
        FakeResponse([FakeChoice(FakeMessage(tool_calls=[
            tool_call("c1", "probe", value="hello"),
        ]))]),
        FakeResponse([FakeChoice(FakeMessage(content="done"))]),
    ])
    agent = LLMAgent(client, "test-model", "sys", {"probe": tool})
    result = agent.run("run the probe")

    assert result.content == "done"
    assert result.rounds == 2
    assert seen == {"value": "hello"}
    assert result.tool_trace == [{
        "tool": "probe", "arguments": '{"value": "hello"}',
        "ok": True, "result": '{"echo": "hello"}',
    }]
    # system prompt + user message + assistant tool_call + tool result
    assert client.calls[0]["messages"][0]["role"] == "system"
    tool_msg = [m for m in client.calls[1]["messages"] if m["role"] == "tool"]
    assert tool_msg and tool_msg[0]["tool_call_id"] == "c1"
    assert "hello" in tool_msg[0]["content"]


def test_agent_unknown_tool_returns_error():
    client = ScriptedClient([
        FakeResponse([FakeChoice(FakeMessage(tool_calls=[
            tool_call("c1", "nope"),
        ]))]),
        FakeResponse([FakeChoice(FakeMessage(content="ok"))]),
    ])
    agent = LLMAgent(client, "m", "s", {})
    result = agent.run("go")
    assert result.tool_trace[0]["ok"] is False
    assert "unknown tool" in result.tool_trace[0]["result"]


def test_agent_invalid_json_arguments():
    client = ScriptedClient([
        FakeResponse([FakeChoice(FakeMessage(tool_calls=[
            FakeToolCall("c1", FakeFunction("probe", "{not json")),
        ]))]),
        FakeResponse([FakeChoice(FakeMessage(content="ok"))]),
    ])
    agent = LLMAgent(client, "m", "s",
                     {"probe": make_tool(lambda **k: "ran")})
    result = agent.run("go")
    assert "invalid JSON" in result.tool_trace[0]["result"]


def test_agent_handler_exception_does_not_raise():
    def boom(**kwargs):
        raise ValueError("exploded")

    client = ScriptedClient([
        FakeResponse([FakeChoice(FakeMessage(tool_calls=[
            tool_call("c1", "probe"),
        ]))]),
        FakeResponse([FakeChoice(FakeMessage(content="recovered"))]),
    ])
    agent = LLMAgent(client, "m", "s", {"probe": make_tool(boom)})
    result = agent.run("go")
    assert result.tool_trace[0]["ok"] is False
    assert "ValueError" in result.tool_trace[0]["result"]
    assert result.content == "recovered"


def test_agent_scope_violation_blocks_handler():
    calls = []
    tool = make_tool(lambda **k: calls.append(k) or "ran",
                     scope_arg="target")
    client = ScriptedClient([
        FakeResponse([FakeChoice(FakeMessage(tool_calls=[
            tool_call("c1", "probe", target="mqtt-gateway"),
        ]))]),
        FakeResponse([FakeChoice(FakeMessage(content="ok"))]),
    ])
    agent = LLMAgent(client, "m", "s", {"probe": tool})
    result = agent.run("go")
    assert calls == []  # handler never executed
    assert "ScopeViolation" in result.tool_trace[0]["result"]


def test_agent_rate_limit_blocks_second_call():
    tool = make_tool(lambda **k: "ran",
                     rate_limit=RateLimiter(min_interval=60.0))
    client = ScriptedClient([
        FakeResponse([FakeChoice(FakeMessage(tool_calls=[
            tool_call("c1", "probe"), tool_call("c2", "probe"),
        ]))]),
        FakeResponse([FakeChoice(FakeMessage(content="ok"))]),
    ])
    agent = LLMAgent(client, "m", "s", {"probe": tool})
    result = agent.run("go")
    assert result.tool_trace[0]["ok"] is True
    assert result.tool_trace[1]["ok"] is False
    assert "RateLimitExceeded" in result.tool_trace[1]["result"]


def test_agent_max_rounds_raises():
    tool_calls = FakeResponse([FakeChoice(FakeMessage(tool_calls=[
        tool_call("c1", "probe"),
    ]))])
    client = ScriptedClient([tool_calls, tool_calls])
    agent = LLMAgent(client, "m", "s", {"probe": make_tool(lambda: "x")},
                     max_rounds=1)
    with pytest.raises(AgentLoopError):
        agent.run("go")


# -- attack agent ---------------------------------------------------------------
class StubDetector:
    """Minimal engine stand-in for ingest wiring tests."""

    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        out = pd.DataFrame(index=df.index)
        out["anomaly_score"] = 0.9
        out["rule_score"] = 0.4
        out["rule_hits"] = [[["stub_rule", "stub reason"]]] * len(df)
        out["fingerprint_score"] = None
        out["fused_score"] = 0.9
        out["is_alert"] = True
        out["confidence"] = 0.9
        out["reasons"] = [["stub reason"]] * len(df)
        out["ml_top_features"] = None
        out["explanation"] = None
        return out


def test_attack_lists_scenarios():
    tools = AttackTools()
    catalog = tools.list_attack_types()
    assert "mqtt_flood" in catalog["scenarios"]
    assert catalog["scenarios"]["mqtt_flood"]["attack_class"] == "DoS"


def test_attack_deploy_unknown_scenario():
    result = AttackTools().deploy_attack("not_a_scenario")
    assert "error" in result and "valid" in result


def test_attack_deploy_without_detection_wiring():
    result = AttackTools().deploy_attack("mqtt_flood", rows=5,
                                         target_device="cam-1")
    assert result["rows"] == 5
    assert result["target_device"] == "cam-1"
    assert result["detection"] == "skipped (no detector/db wired)"


def test_attack_deploy_with_detection_wiring(tmp_path):
    db = Database(tmp_path / "a.db").init()
    tools = AttackTools(detector=StubDetector(), db=db)
    result = tools.deploy_attack("mqtt_flood", rows=4, target_device="cam-1")
    assert result["alerts_flagged"] == 4
    assert len(result["alert_ids"]) == 4
    alert = db.get_alert(result["alert_ids"][0])
    assert alert["device_id"] == "cam-1"
    assert alert["attack_class"] == "DoS"
    audit = db.list_audit()
    assert any(e["action"] == "scenario_deployed" for e in audit)


def test_attack_deploy_protected_target_denied():
    tools = AttackTools(scope=ScopePolicy())
    with pytest.raises(ScopeViolation):
        tools.deploy_attack("mqtt_flood", target_device="the-gateway")


def test_attack_deploy_rate_limited_via_agent():
    tools = build_attack_tools()
    spec = tools["deploy_attack"]
    ok1, _out1 = spec_to_executor(spec, {"scenario": "mqtt_flood"})
    ok2, out2 = spec_to_executor(spec, {"scenario": "mqtt_flood"})
    assert ok1 is True and ok2 is False
    assert "RateLimitExceeded" in out2


def spec_to_executor(spec: ToolSpec, args: dict):
    """Run one ToolSpec through an agent-less guardrail check."""
    agent = SimpleNamespace(_scope=ScopePolicy(), tools={spec.name: spec})
    return LLMAgent.execute_tool(agent, spec.name, json.dumps(args))


def test_build_attack_agent_shape():
    agent = build_attack_agent(client=ScriptedClient([]))
    assert agent.model == "deepseek-chat"
    assert set(agent.tools) == {
        "list_attack_types", "deploy_attack", "get_network_state",
    }


def test_attack_network_state(tmp_path):
    db = Database(tmp_path / "n.db").init()
    db.upsert_device("cam-1")
    state = AttackTools(db=db).get_network_state()
    assert state["devices"][0]["device_id"] == "cam-1"
    assert AttackTools().get_network_state()["note"]


# -- defense agent & response policy ----------------------------------------------
@pytest.fixture()
def db(tmp_path):
    database = Database(tmp_path / "d.db").init()
    database.upsert_device("cam-1")
    database.upsert_device("thermo-2")
    high = database.insert_alert(device_id="cam-1", attack_class="DoS",
                                 confidence=0.95, fused_score=0.95,
                                 status="open")
    low = database.insert_alert(device_id="thermo-2", attack_class="DoS",
                                confidence=0.20, fused_score=0.20,
                                status="open")
    return database, high, low


def test_defense_alert_details(db):
    database, high, _ = db
    details = DefenseTools(database).get_alert_details(high)
    assert details["device_id"] == "cam-1"
    assert "features" not in details
    assert DefenseTools(database).get_alert_details(999)["error"]


def test_defense_correlate_clusters(db):
    database, _high, _low = db
    clusters = DefenseTools(database).correlate_alerts()
    by_key = {(c["device_id"], c["attack_class"]): c for c in clusters["clusters"]}
    assert by_key[("cam-1", "DoS")]["avg_confidence"] == 0.95
    assert by_key[("thermo-2", "DoS")]["alert_count"] == 1


def test_defense_incident_and_timeline(db):
    database, high, _ = db
    tools = DefenseTools(database)
    incident = tools.create_incident("Flood campaign", [high])
    assert incident["incident_id"] > 0
    event = tools.append_timeline_event(incident["incident_id"],
                                        "investigation", "correlated 1 alert")
    assert event["event_id"] > 0
    timeline = database.get_timeline(incident["incident_id"])
    assert any("correlated 1 alert" in e["message"] for e in timeline)
    assert tools.append_timeline_event(999, "x", "y")["error"]


def test_request_isolation_success_flow(db):
    database, high, _ = db
    tools = DefenseTools(database)
    incident = tools.create_incident("confirmed flood")
    result = tools.request_isolation("cam-1", alert_id=high,
                                     incident_id=incident["incident_id"],
                                     reason="confirmed DoS")
    assert result["status"] == "isolated"
    device = {d["device_id"]: d for d in database.list_devices()}["cam-1"]
    assert device["status"] == "isolated"
    assert any(e["action"] == "device_isolated" for e in database.list_audit())
    timeline = database.get_timeline(incident["incident_id"])
    assert any("isolated by policy-bounded response" in e["message"]
               for e in timeline)


def test_request_isolation_weak_confidence_denied(db):
    database, _, low = db
    result = DefenseTools(database).request_isolation("thermo-2", alert_id=low)
    assert result["denied"] is True
    assert "confidence" in result["reason"]
    device = {d["device_id"]: d for d in database.list_devices()}["thermo-2"]
    assert device["status"] == "trusted"


def test_request_isolation_unknown_device_denied(db):
    database, high, _ = db
    result = DefenseTools(database).request_isolation("ghost-device",
                                                      alert_id=high)
    assert result["denied"] is True
    assert "unknown device" in result["reason"]


def test_response_policy_protected_devices():
    policy = ResponsePolicy()
    for bad in ("gateway", "mqtt-broker-2", "SOC-server"):
        with pytest.raises(IsolationDenied):
            policy.check_isolation(bad, confidence=0.99)


def test_response_policy_rate_bounded():
    clock = FakeClock()
    policy = ResponsePolicy(max_isolations=2, window_seconds=60, clock=clock)
    policy.check_isolation("cam-1", 0.9)
    policy.check_isolation("cam-2", 0.9)
    with pytest.raises(IsolationDenied):
        policy.check_isolation("cam-3", 0.9)
    clock.now += 61
    policy.check_isolation("cam-3", 0.9)  # window expired


def test_release_device(db):
    database, high, _ = db
    execute_isolation(database, "cam-1", alert_id=high)
    released = release_device(database, "cam-1", released_by="operator",
                              reason="false positive confirmed")
    assert released["status"] == "trusted"
    assert any(e["action"] == "device_released" for e in database.list_audit())


def test_build_defense_agent_shape(tmp_path):
    db = Database(tmp_path / "shape.db").init()
    agent = build_defense_agent(client=ScriptedClient([]), db=db)
    assert agent.model == "llama-3.3-70b-versatile"
    assert set(agent.tools) == {
        "get_alert_details", "list_open_alerts", "correlate_alerts",
        "create_incident", "append_timeline_event", "request_isolation",
    }


def test_full_loop_defense_isolates_via_fake_llm(db):
    """End-to-end: scripted LLM calls tools; isolation lands in the DB."""
    database, high, _ = db
    client = ScriptedClient([
        FakeResponse([FakeChoice(FakeMessage(tool_calls=[
            tool_call("c1", "get_alert_details", alert_id=high),
            tool_call("c2", "request_isolation", device_id="cam-1",
                      alert_id=high, reason="confirmed by LLM"),
        ]))]),
        FakeResponse([FakeChoice(FakeMessage(content="isolated cam-1"))]),
    ])
    agent = build_defense_agent(client=client, db=database)
    result = agent.run("investigate and respond")
    assert result.content == "isolated cam-1"
    assert all(t["ok"] for t in result.tool_trace)
    device = {d["device_id"]: d for d in database.list_devices()}["cam-1"]
    assert device["status"] == "isolated"
