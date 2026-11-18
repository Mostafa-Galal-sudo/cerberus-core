"""DeepSeek-powered attack agent — red-team traffic generator for the testbed.

Generates and deploys *simulated* attack scenarios (detection/simulator.py)
against lab devices so the detection loop has something to catch. Safety:

- Deployed traffic is always locally simulated; nothing touches a real
  network (AGENTS.md safety rules).
- Scope locking: `target_device` is validated against protected
  infrastructure names; the gateway/broker/SOC can never be targeted.
- Rate limiting: deployments are capped (min interval + per-window budget).

The LLM client is any OpenAI-SDK-shaped object; the real DeepSeek client
(base_url https://api.deepseek.com) is created lazily so tests never need it.
"""
from __future__ import annotations

from typing import Any

import config
from agents.scaffold import LLMAgent, RateLimiter, ScopePolicy, ToolSpec
from detection.simulator import SIM_SCENARIOS, generate_traffic

DEEPSEEK_BASE_URL = "https://api.deepseek.com"

_SYSTEM_PROMPT = """\
You are CERBERUS's red-team agent for a LOCAL lab testbed. Your job is to
generate simulated attack traffic so the detection pipeline can be validated.
Rules you must never break:
- You may only deploy the predefined scenarios returned by list_attack_types.
- You may only target devices that exist in the network state; the gateway,
  MQTT broker, and SOC infrastructure are protected and off-limits.
- Deploy sparingly: deployments are rate-limited and every call is audited.
When asked to test detection, pick a scenario, deploy it, and report what the
pipeline recorded."""


class AttackTools:
    """Tool handlers for the attack agent (kept free of LLM specifics)."""

    def __init__(
        self,
        detector: Any = None,
        db: Any = None,
        scope: ScopePolicy | None = None,
    ):
        self.detector = detector  # optional fitted HybridDetector
        self.db = db              # optional backend.db.Database
        self.scope = scope or ScopePolicy()

    # -- tools ----------------------------------------------------------------
    def list_attack_types(self) -> dict:
        catalog = {}
        for scenario, (label, attack_class, is_attack) in SIM_SCENARIOS.items():
            catalog[scenario] = {
                "label": label,
                "attack_class": attack_class,
                "is_attack": bool(is_attack),
            }
        return {"scenarios": catalog}

    def deploy_attack(
        self,
        scenario: str,
        rows: int = 20,
        target_device: str = "lab-target",
        seed: int = 42,
    ) -> dict:
        """Generate simulated traffic for `scenario` against a lab device.

        With a detector + db wired, the traffic is scored through the hybrid
        engine and persisted as alerts; otherwise a summary is returned.
        """
        self.scope.check(target_device)  # defense in depth (loop also checks)
        if scenario not in SIM_SCENARIOS:
            return {"error": f"unknown scenario '{scenario}'",
                    "valid": sorted(SIM_SCENARIOS)}
        rows = max(1, min(int(rows), 500))
        df = generate_traffic({scenario: rows}, seed=seed)
        df["device_id"] = target_device
        label, attack_class, _ = SIM_SCENARIOS[scenario]

        result: dict[str, Any] = {
            "scenario": scenario,
            "label": label,
            "attack_class": attack_class,
            "rows": rows,
            "target_device": target_device,
        }
        if self.detector is not None and self.db is not None:
            from backend.ingest import ingest

            alerts = self.detector.score(df)
            ids = ingest(df, alerts, self.db)
            result["alert_ids"] = ids
            result["alerts_flagged"] = len(ids)
            self.db.audit("attack-agent", "scenario_deployed", {
                "scenario": scenario, "rows": rows,
                "target_device": target_device, "seed": seed,
                "alerts_flagged": len(ids),
            })
        else:
            result["detection"] = "skipped (no detector/db wired)"
        return result

    def get_network_state(self) -> dict:
        if self.db is None:
            return {"devices": [], "note": "no database wired"}
        devices = [
            {
                "device_id": d["device_id"],
                "status": d["status"],
                "last_seen": d["last_seen"],
            }
            for d in self.db.list_devices()
        ]
        return {"devices": devices}


def build_attack_tools(**kwargs: Any) -> dict[str, ToolSpec]:
    tools = AttackTools(**kwargs)
    return {
        "list_attack_types": ToolSpec(
            name="list_attack_types",
            description="List the deployable simulated attack scenarios with "
                        "their labels and attack classes.",
            parameters={"type": "object", "properties": {}},
            handler=tools.list_attack_types,
        ),
        "deploy_attack": ToolSpec(
            name="deploy_attack",
            description="Deploy a simulated attack scenario against a lab "
                        "device. Generates synthetic traffic in the "
                        "CICIoT2023 schema and (if wired) runs it through "
                        "the detection engine.",
            parameters={
                "type": "object",
                "properties": {
                    "scenario": {"type": "string",
                                 "description": "Scenario key from "
                                                "list_attack_types"},
                    "rows": {"type": "integer", "minimum": 1, "maximum": 500},
                    "target_device": {"type": "string",
                                      "description": "Lab device id to "
                                                     "target"},
                    "seed": {"type": "integer"},
                },
                "required": ["scenario"],
            },
            handler=tools.deploy_attack,
            scope_arg="target_device",
            rate_limit=RateLimiter(min_interval=2.0, max_per_window=10,
                                   window_seconds=60.0),
        ),
        "get_network_state": ToolSpec(
            name="get_network_state",
            description="List devices in the testbed registry with their "
                        "status and last-seen time.",
            parameters={"type": "object", "properties": {}},
            handler=tools.get_network_state,
        ),
    }


def build_attack_agent(
    client: Any = None,
    model: str | None = None,
    **tool_kwargs: Any,
) -> LLMAgent:
    """Assemble the DeepSeek attack agent. `client=None` builds the real one."""
    if client is None:
        from openai import OpenAI  # lazy: only real runs need the SDK

        client = OpenAI(base_url=DEEPSEEK_BASE_URL,
                        api_key=config.DEEPSEEK_API_KEY)
    return LLMAgent(
        client=client,
        model=model or config.DEEPSEEK_MODEL,
        system_prompt=_SYSTEM_PROMPT,
        tools=build_attack_tools(**tool_kwargs),
    )
