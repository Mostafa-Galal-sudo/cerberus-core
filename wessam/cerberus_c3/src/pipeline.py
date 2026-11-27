"""Closed loop: detection -> evidence -> recommendation -> policy -> response -> outcome (all in the incident timeline)."""
from __future__ import annotations

from src.agents.tools import EvidenceTools
from src.incidents import Detection, EventType, Incident, IncidentStore
from src.policy import ActionRequest, PolicyEngine
from src.response import ResponseExecutor


def handle_detection(detection: Detection, *, store: IncidentStore, tools: EvidenceTools,
                     agent, policy: PolicyEngine, executor: ResponseExecutor) -> Incident:
    inc = store.create(detection)
    inc.status = "investigating"

    rec = agent.investigate(detection, tools)
    for c in tools.calls:                                       # evidence entries
        inc.add_event(EventType.EVIDENCE, "evidence_tools",
                      f"{c['evidence_id']} {c['tool']}({c['args']})", c["result"], ts=c["ts"])

    inc.add_event(EventType.DECISION, f"defense_agent[{rec.source}]",
                  f"{rec.verdict} (conf {rec.confidence:.2f}) -> propose {rec.recommended_action} on {rec.target}: {rec.summary}",
                  rec.model_dump())

    decision = policy.evaluate(ActionRequest(
        actor="defense_agent", action=rec.recommended_action, target=rec.target,
        params=rec.params, confidence=rec.confidence, incident_id=inc.id))
    inc.add_event(EventType.DECISION, "policy",
                  f"{'ALLOWED' if decision.allowed else 'DENIED'}: {decision.reason}", decision.to_dict())

    if decision.allowed:
        executor.execute(decision.token, inc)
    else:
        inc.status = "not_contained"
        inc.add_event(EventType.OUTCOME, "response_layer", "no action executed (denied by policy)")
        store.save(inc)
    return inc
