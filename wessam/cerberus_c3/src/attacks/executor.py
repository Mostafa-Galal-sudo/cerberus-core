"""C3-T05 (execution half) — attack plans run ONLY through the policy layer."""
from __future__ import annotations

from src.policy import ApprovedDecision, PolicyEngine

from .simulator import SimWorld


class AttackExecutor:
    def __init__(self, world: SimWorld, policy: PolicyEngine):
        self.world, self.policy = world, policy

    def execute(self, token: ApprovedDecision) -> dict:
        req = self.policy.consume(token, expected_actor="attack_agent")   # raises without approval
        p = req.params
        atk = self.world.start_attack(req.action, p["source"], req.target,
                                      p["rate_msgs_per_s"], p["duration_s"])
        return {"action": req.action, "source": atk.source, "target": atk.target,
                "rate_msgs_per_s": atk.rate, "ends_at_sim_t": atk.until}
