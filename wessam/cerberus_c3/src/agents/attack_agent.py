"""C3-T05 — Attack agent (DeepSeek). Generates attack PLANS against the *simulated* testbed.
It cannot execute anything: every step goes through PolicyEngine -> AttackExecutor.
"""
from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from src.attacks.executor import AttackExecutor
from src.policy import ActionRequest, PolicyEngine

from .defense_agent import _extract_json


class AttackStep(BaseModel):
    action: Literal["sim_mqtt_flood", "sim_injection", "sim_spoofed_identity"]
    source: str
    target: str
    params: dict = Field(default_factory=dict)   # rate_msgs_per_s, duration_s (source is added from `source`)


class AttackPlan(BaseModel):
    goal: str = ""
    steps: list[AttackStep]


SCRIPTED = {
    "flood": AttackPlan(goal="MQTT flood from rogue device", steps=[AttackStep(
        action="sim_mqtt_flood", source="esp32-05", target="broker",
        params={"rate_msgs_per_s": 100, "duration_s": 40})]),
    "injection": AttackPlan(goal="command injection toward esp32-03", steps=[AttackStep(
        action="sim_injection", source="esp32-05", target="esp32-03",
        params={"rate_msgs_per_s": 5, "duration_s": 40})]),
    "spoof": AttackPlan(goal="spoof esp32-02 identity", steps=[AttackStep(
        action="sim_spoofed_identity", source="esp32-05", target="esp32-02",
        params={"rate_msgs_per_s": 10, "duration_s": 40})]),
}


class AttackAgent:
    def __init__(self, client=None, model: str | None = None):
        self.client, self.model = client, model

    def plan(self, scenario: str, policy: PolicyEngine) -> AttackPlan:
        """LLM plan if a client is configured; otherwise (or on any failure) the scripted plan."""
        if self.client is None:
            return SCRIPTED[scenario]
        catalog = json.dumps(policy.describe_actions("attack_agent"), indent=1)
        system = (f"You plan attacks against a SIMULATED IoT testbed to validate a defense system. "
                  f"Devices: {policy.scope['devices']} (+ 'broker'). The rogue device is esp32-05. "
                  f"Allowed attack actions and param limits:\n{catalog}\n"
                  'Reply with ONLY JSON: {"goal":"...","steps":[{"action":"...","source":"esp32-05",'
                  '"target":"...","params":{"rate_msgs_per_s":N,"duration_s":N}}]} (max 3 steps).')
        try:
            r = self.client.chat.completions.create(
                model=self.model, temperature=0.3,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": f"Scenario: {scenario}"}])
            plan = AttackPlan.model_validate(_extract_json(r.choices[0].message.content))
            return AttackPlan(goal=plan.goal, steps=plan.steps[:3])
        except (ValidationError, ValueError, json.JSONDecodeError, Exception):
            return SCRIPTED[scenario]


def run_plan(plan: AttackPlan, policy: PolicyEngine, executor: AttackExecutor) -> list[dict]:
    """Every step is evaluated by the policy; denied steps are reported, never executed."""
    results = []
    for step in plan.steps:
        params = {"source": step.source, **step.params}
        d = policy.evaluate(ActionRequest(actor="attack_agent", action=step.action,
                                          target=step.target, params=params))
        if d.allowed:
            results.append({"allowed": True, **executor.execute(d.token)})
        else:
            results.append({"allowed": False, "action": step.action, "reason": d.reason})
    return results
