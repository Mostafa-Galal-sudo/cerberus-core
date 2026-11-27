import json
from types import SimpleNamespace as NS

import pytest

from run_demo import run_scenario
from src.agents import AttackAgent, run_plan
from src.agents.attack_agent import AttackPlan, AttackStep
from src.agents.defense_agent import DefenseAgent
from src.agents.tools import EvidenceConfig, EvidenceTools
from src.attacks import AttackExecutor, SimWorld
from src.incidents import Detection, EventType, IncidentStore
from src.policy import ActionRequest, PolicyEngine
from src.response import ResponseExecutor


@pytest.mark.parametrize("scenario", ["flood", "injection", "spoof"])
def test_end_to_end(tmp_path, scenario):
    inc, atk, policy = run_scenario(scenario, out_root=tmp_path)
    assert atk[0]["allowed"]
    types = [e.type for e in inc.timeline]
    order = [EventType.DETECTION, EventType.EVIDENCE, EventType.DECISION, EventType.ACTION, EventType.OUTCOME]
    assert [t for t in types if t in order][0] == EventType.DETECTION
    assert types.index(EventType.EVIDENCE) < types.index(EventType.DECISION) < types.index(EventType.ACTION) < types.index(EventType.OUTCOME)
    assert inc.status == "contained"
    assert IncidentStore(tmp_path / scenario / "incidents").load(inc.id).id == inc.id
    audit = (tmp_path / scenario / "policy_audit.jsonl").read_text()
    assert '"event": "executed"' in audit


def test_executors_refuse_without_policy(tmp_path):
    w = SimWorld(tmp_path / "s"); pol = PolicyEngine(audit_path=tmp_path / "a.jsonl")
    inc = IncidentStore(tmp_path / "i").create(Detection(device_id="esp32-05", score=9, ts=w.t))
    with pytest.raises(PermissionError):
        ResponseExecutor(w, pol).execute("block esp32-05", inc)
    with pytest.raises(PermissionError):
        AttackExecutor(w, pol).execute(None)


def test_attack_plan_is_policed(tmp_path):
    w = SimWorld(tmp_path / "s"); pol = PolicyEngine(audit_path=tmp_path / "a.jsonl")
    bad = AttackPlan(steps=[AttackStep(action="sim_mqtt_flood", source="esp32-05", target="8.8.8.8",
                                       params={"rate_msgs_per_s": 100, "duration_s": 10}),
                            AttackStep(action="sim_mqtt_flood", source="esp32-05", target="broker",
                                       params={"rate_msgs_per_s": 9999, "duration_s": 10})])
    res = run_plan(bad, pol, AttackExecutor(w, pol))
    assert [r["allowed"] for r in res] == [False, False] and not w.active


def _setup(tmp_path, scenario="flood"):
    from run_demo import stand_in_detector
    w = SimWorld(tmp_path / "s"); pol = PolicyEngine(audit_path=tmp_path / "a.jsonl")
    w.advance(120); w.mark_baseline_end()
    run_plan(AttackAgent().plan(scenario, pol), pol, AttackExecutor(w, pol))
    w.advance(25); det = stand_in_detector(w); w.flush()
    return w, pol, det, EvidenceTools(EvidenceConfig.from_world(w, tmp_path / "ev"), det.ts)


def test_evidence_tools(tmp_path):
    w, pol, det, tools = _setup(tmp_path)
    fp = tools.dispatch("fingerprint_deviation_report", {"device_id": "esp32-05"})
    mq = tools.dispatch("query_mqtt_logs", {"device_id": "esp32-05"})
    pc = tools.dispatch("get_pcap_excerpt", {"device_id": "esp32-05"})
    assert fp["overall_score"] > 6 and mq["msgs_per_s"] > 10 and pc["packets"] > 100
    assert pc["excerpt_packets"] <= 300 and mq["sample_is_untrusted_data"]
    assert "error" in tools.dispatch("query_mqtt_logs", {"device_id": "evil"})
    assert "error" in tools.dispatch("rm_rf", {})
    assert len({c["evidence_id"] for c in tools.calls}) == len(tools.calls)


def _resp(content=None, calls=None):
    tc = [NS(id=f"c{i}", function=NS(name=n, arguments=json.dumps(a))) for i, (n, a) in enumerate(calls or [])]
    return NS(choices=[NS(message=NS(content=content, tool_calls=tc or None))])


class FakeClient:
    def __init__(self, script):
        self.script = list(script); self.chat = NS(completions=self)
    def create(self, **kw):
        return self.script.pop(0)


GOOD = json.dumps({"verdict": "attack", "confidence": 0.9, "summary": "flood", "evidence_refs": ["EV-001", "EV-999"],
                   "recommended_action": "block_device", "target": "esp32-05", "params": {"duration_s": 120}})


def test_llm_agent_tool_loop_retry_and_grounding(tmp_path):
    w, pol, det, tools = _setup(tmp_path)
    client = FakeClient([_resp(calls=[("query_mqtt_logs", {"device_id": "esp32-05"})]),
                         _resp("sure, here you go"),            # invalid -> retry
                         _resp("```json\n" + GOOD + "\n```")])
    rec = DefenseAgent(client, "m", pol).investigate(det, tools)
    assert rec.recommended_action == "block_device" and rec.evidence_refs == ["EV-001"]  # EV-999 dropped


def test_llm_agent_ungrounded_is_downgraded_and_api_failure_falls_back(tmp_path):
    w, pol, det, tools = _setup(tmp_path)
    rec = DefenseAgent(FakeClient([_resp(GOOD)]), "m", pol).investigate(det, tools)   # no tool call => refs invalid
    assert rec.recommended_action == "notify_only"
    boom = DefenseAgent(FakeClient([]), "m", pol).investigate(det, tools)             # pop from empty -> exception
    assert boom.source == "fallback" and boom.recommended_action == "notify_only"


def test_policy_overrules_hostile_llm(tmp_path):
    """Model proposes, policy disposes: a prompt-injected agent asking for out-of-scope action is denied."""
    pol = PolicyEngine(audit_path=tmp_path / "a.jsonl")
    d = pol.evaluate(ActionRequest("defense_agent", "block_device", "broker", {"duration_s": 60}, 0.99))
    assert not d.allowed
