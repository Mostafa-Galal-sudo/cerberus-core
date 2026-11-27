from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from dotenv import load_dotenv

from src.policy import PolicyDecision, PolicyGate
from src.simulator.anomalies import (
    inject_payload_bloat,
    inject_rate_flood,
    inject_rogue_device,
)

from .fallback import fallback_attack_plan
from .provider import ProviderAdapter

DEFAULT_DEEPSEEK_MODEL = "deepseek-chat"  # legacy compatibility alias
DEEPSEEK_BASE_URL = "https://api.deepseek.com"  # legacy compatibility alias

_SYSTEM_PROMPT = (
    "You are the Cerberus Red-Team Simulator Agent. "
    "Propose one bounded MQTT lab anomaly scenario as JSON ONLY: "
    '{"action": "attack_flood"|"attack_bloat"|"attack_rogue", "target": "<device_id>", "topic": "lab/...", "reason": "<short>"}.'
)


@dataclass
class AttackExecutionResult:
    mode: str  # "llm" or "fallback"
    executed: bool
    decision: PolicyDecision
    events_injected: int = 0
    plan: dict[str, Any] | None = None
    error: str | None = None
    provider: str | None = None
    model: str | None = None


class AttackAgent:
    """Provider-agnostic attack proposer; every execution routes through PolicyGate."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        gate: PolicyGate,
        *,
        mqtt_client: Any = None,
        client: Any = None,
        model: str | None = None,
        provider: str | None = None,
        assignment_key: str | None = None,
    ) -> None:
        load_dotenv()
        self.conn = conn
        self.gate = gate
        self.mqtt_client = mqtt_client
        self.adapter = ProviderAdapter(
            role="attack",
            client=client,
            provider=provider or ("injected" if client is not None else None),
            model=model,
            assignment_key=assignment_key,
        )
        self.model = model
        self.last_provider = self.adapter.provider
        self.last_model: str | None = None

    def propose(self, prompt: str = "Generate a lab MQTT anomaly test.") -> tuple[str, dict[str, Any], str | None]:
        self.last_provider = self.adapter.provider
        self.last_model = self.adapter.status().model
        if not self.adapter.status().configured:
            return "fallback", fallback_attack_plan(), None

        try:
            result = self.adapter.complete(
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
            )
            plan = json.loads(result.content or "{}")
            plan["mode"] = "llm"
            plan["provider"] = result.provider
            plan["model"] = result.model
            return "llm", plan, None
        except Exception as exc:
            return "fallback", fallback_attack_plan(), str(exc)

    def run_scenario(
        self,
        prompt: str = "Generate a lab MQTT anomaly test.",
        *,
        count: int = 10,
        interval: float = 0.0,
    ) -> AttackExecutionResult:
        mode, plan, err = self.propose(prompt)
        action = str(plan.get("action") or "attack_flood")
        target = str(plan.get("target") or "esp32_temp_01")
        topic = plan.get("topic", "lab/room1/climate")

        decision = self.gate.authorize(
            "attack",
            action,
            target,
            context={
                "topic": topic,
                "mode": mode,
                "reason": plan.get("reason", ""),
                "provider": self.last_provider,
                "model": self.last_model,
            },
        )
        if not decision.allowed:
            return AttackExecutionResult(
                mode=mode,
                executed=False,
                decision=decision,
                events_injected=0,
                plan=plan,
                error=err,
                provider=self.last_provider,
                model=self.last_model,
            )

        if action == "attack_flood":
            injected = inject_rate_flood(
                self.mqtt_client,
                self.conn,
                device_id=target,
                topic=topic or "lab/room1/climate",
                count=count,
                interval=interval,
                decision=decision,
            )
        elif action == "attack_bloat":
            injected = inject_payload_bloat(
                self.mqtt_client,
                self.conn,
                device_id=target,
                topic=topic or "lab/room1/power",
                count=count,
                interval=interval,
                decision=decision,
            )
        elif action == "attack_rogue":
            injected = inject_rogue_device(
                self.mqtt_client,
                self.conn,
                device_id=target,
                topic=topic or "lab/room9/unknown",
                count=count,
                interval=interval,
                decision=decision,
            )
        else:
            injected = 0

        return AttackExecutionResult(
            mode=mode,
            executed=injected > 0,
            decision=decision,
            events_injected=injected,
            plan=plan,
            error=err,
            provider=self.last_provider,
            model=self.last_model,
        )
