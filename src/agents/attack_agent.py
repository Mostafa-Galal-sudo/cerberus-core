from __future__ import annotations

import json
import os
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

DEFAULT_DEEPSEEK_MODEL = "deepseek-chat"
DEEPSEEK_BASE_URL = "https://api.deepseek.com"

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


class AttackAgent:
    """DeepSeek-powered attack proposer; every execution routes through PolicyGate."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        gate: PolicyGate,
        *,
        mqtt_client: Any = None,
        client: Any = None,
        model: str = DEFAULT_DEEPSEEK_MODEL,
    ) -> None:
        load_dotenv()
        self.conn = conn
        self.gate = gate
        self.mqtt_client = mqtt_client
        self._client = client
        self.model = model

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        api_key = os.environ.get("DEEPSEEK_API_KEY")
        if not api_key:
            return None
        from openai import OpenAI

        self._client = OpenAI(api_key=api_key, base_url=DEEPSEEK_BASE_URL)
        return self._client

    def propose(self, prompt: str = "Generate a lab MQTT anomaly test.") -> tuple[str, dict[str, Any], str | None]:
        try:
            client = self._get_client()
        except Exception as exc:
            return "fallback", fallback_attack_plan(), str(exc)
        if client is None:
            return "fallback", fallback_attack_plan(), None

        try:
            resp = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
            )
            content = resp.choices[0].message.content or "{}"
            plan = json.loads(content)
            plan["mode"] = "llm"
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
            context={"topic": topic, "mode": mode, "reason": plan.get("reason", "")},
        )
        if not decision.allowed:
            return AttackExecutionResult(
                mode=mode,
                executed=False,
                decision=decision,
                events_injected=0,
                plan=plan,
                error=err,
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
        )
