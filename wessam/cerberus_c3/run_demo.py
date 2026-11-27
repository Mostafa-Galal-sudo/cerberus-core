"""Checkpoint 3 demo — full closed loop with ZERO hardware.
    python run_demo.py [flood|injection|spoof|all] [--llm]
Without --llm (or without API keys) the offline rule-based agents are used.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

from src.agents import AttackAgent, RuleBasedDefenseAgent, run_plan
from src.agents.defense_agent import DefenseAgent
from src.agents.llm import has_key, make_client
from src.agents.tools import EvidenceConfig, EvidenceTools
from src.attacks import AttackExecutor, SimWorld
from src.attacks.simulator import DEVICES
from src.incidents import Detection, IncidentStore
from src.pipeline import handle_detection
from src.policy import PolicyEngine
from src.response import ResponseExecutor


def stand_in_detector(world: SimWorld, threshold: float = 6.0) -> Detection | None:
    """Tiny z-score detector so the demo is self-contained. Replace with src/detection (your hybrid IDS)."""
    best = None
    for r in world.feature_rows[-len(DEVICES) * 2:]:           # last 2 windows
        base = world.baseline[r["device_id"]]
        for f, v in r["features"].items():
            b = base[f]
            z = abs(v - b["mean"]) / max(b["std"], 0.05 * max(abs(b["mean"]), 1.0))
            if z >= threshold and (best is None or z > best.score):
                best = Detection(device_id=r["device_id"], score=round(z, 1), ts=world.t,
                                 attack_type_hint=f"anomalous {f}", features=r["features"])
    return best


def run_scenario(scenario: str, out_root: str = "results/demo", use_llm: bool = False, seed: int = 7):
    out = Path(out_root) / scenario
    shutil.rmtree(out, ignore_errors=True)
    world = SimWorld(out / "sim", seed=seed)
    policy = PolicyEngine(audit_path=out / "policy_audit.jsonl")
    store = IncidentStore(out / "incidents")

    world.advance(120)                                          # learn normal behaviour
    world.mark_baseline_end()

    atk_client = atk_model = None
    if use_llm and has_key("deepseek"):
        atk_client, atk_model = make_client("deepseek")
    plan = AttackAgent(atk_client, atk_model).plan(scenario, policy)
    attack_results = run_plan(plan, policy, AttackExecutor(world, policy))

    world.advance(25)                                           # attack runs
    detection = stand_in_detector(world)
    if detection is None:
        return None, attack_results, policy
    world.flush()

    if use_llm and has_key("groq"):
        client, model = make_client("groq")
        agent = DefenseAgent(client, model, policy)
    else:
        agent = RuleBasedDefenseAgent()
    tools = EvidenceTools(EvidenceConfig.from_world(world, out / "evidence"), t_ref=detection.ts)
    incident = handle_detection(detection, store=store, tools=tools, agent=agent, policy=policy,
                                executor=ResponseExecutor(world, policy, store))
    world.flush()
    return incident, attack_results, policy


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    scenarios = ["flood", "injection", "spoof"] if (not args or args[0] == "all") else [args[0]]
    for s in scenarios:
        inc, atk, _ = run_scenario(s, use_llm="--llm" in sys.argv)
        print(f"\n=== scenario: {s} ===\nattack plan results: {atk}")
        print(inc.render() if inc else "NO DETECTION")
