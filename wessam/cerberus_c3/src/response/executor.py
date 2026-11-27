"""C3-T06 — Response layer: automatic isolation of a confirmed attacker (simulator world) + audit trail.
Accepts ONLY an ApprovedDecision issued by the policy layer.
"""
from __future__ import annotations

from src.attacks.simulator import SimWorld
from src.incidents import EventType, Incident, IncidentStore
from src.policy import ApprovedDecision, PolicyEngine


class ResponseExecutor:
    def __init__(self, world: SimWorld, policy: PolicyEngine, store: IncidentStore | None = None):
        self.world, self.policy, self.store = world, policy, store

    def execute(self, token: ApprovedDecision, incident: Incident, hold_s: int = 20) -> Incident:
        req = self.policy.consume(token, expected_actor="defense_agent")   # raises without approval
        w = self.world
        dev = req.target if req.target in w.devices else incident.device_id
        before = w.rate_of(dev, 10)

        if req.action == "block_device":
            w.block_device(req.target, req.params["duration_s"]); effect = f"{req.target} blocked for {req.params['duration_s']}s"
        elif req.action == "rate_limit":
            w.rate_limit_device(req.target, req.params["max_msgs_per_sec"]); effect = f"{req.target} limited to {req.params['max_msgs_per_sec']} msg/s"
        elif req.action == "quarantine_topic":
            w.quarantine_topic(req.target); effect = f"topic {req.target} quarantined"
        else:
            effect = "operator notified (no containment applied)"
        incident.add_event(EventType.ACTION, "response_layer", effect,
                           {"decision_id": token.decision_id, "action": req.action,
                            "target": req.target, "params": req.params})

        w.advance(hold_s)                                       # observe the effect in the simulator
        after = w.rate_of(dev, 10)
        contained = req.action != "notify_only" and after <= max(1.0, 0.2 * before)
        incident.status = "contained" if contained else "not_contained"
        incident.add_event(EventType.OUTCOME, "response_layer",
                           f"{'CONTAINED' if contained else 'NOT contained'}: {dev} rate {before:.1f} -> {after:.1f} msg/s",
                           {"rate_before": before, "rate_after": after, "contained": contained,
                            "dropped_msgs": w.dropped[dev]})
        if self.store:
            self.store.save(incident)
        return incident
