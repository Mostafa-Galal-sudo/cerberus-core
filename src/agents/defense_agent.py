from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from dotenv import load_dotenv

from src.agents.tools import (
    device_deviation_report,
    extract_pcap_excerpt,
    query_device_events,
    query_incident_history,
)
from src.detection.fingerprint import DeviceFingerprint
from src.incidents import IncidentRecord, IncidentStore
from src.policy import PolicyGate
from src.response import IsolationResult, isolate_device

from .fallback import fallback_investigate
from .provider import ProviderAdapter

DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"  # legacy compatibility alias

DEFENSE_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "query_device_events",
            "description": "Fetch recent MQTT events for a device from SQLite.",
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {"type": "string"},
                    "limit": {"type": "integer", "default": 15},
                },
                "required": ["device_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "device_deviation_report",
            "description": "Compute per-device behavioral fingerprint deviation report.",
            "parameters": {
                "type": "object",
                "properties": {"device_id": {"type": "string"}},
                "required": ["device_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_incident_history",
            "description": "List recent incidents for a device.",
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {"type": "string"},
                    "limit": {"type": "integer", "default": 5},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_pcap_excerpt",
            "description": "Extract packet summaries around a detection if PCAP exists.",
            "parameters": {
                "type": "object",
                "properties": {"device_ip": {"type": "string"}},
            },
        },
    },
]

_SYSTEM_PROMPT = (
    "You are the Cerberus IoT SOC Defense Agent. "
    "Investigate the detection using the read-only tools, then respond ONLY with JSON: "
    '{"recommended_action": "isolate_device" | "log_alert", "severity": "low"|"medium"|"high"|"critical", "summary": "<concise reason>"}.'
)


@dataclass
class DefenseResult:
    mode: str  # "llm" or "fallback"
    incident: IncidentRecord
    isolation: IsolationResult | None = None
    error: str | None = None
    provider: str | None = None
    model: str | None = None


class DefenseAgent:
    """Provider-agnostic defense agent with tool-calling and deterministic fallback.

    The model proposes; ``PolicyGate`` disposes. Any provider/configuration
    error routes to ``fallback_investigate`` without raising to the caller.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        gate: PolicyGate,
        incidents: IncidentStore | None = None,
        *,
        fingerprint: DeviceFingerprint | None = None,
        pcap_path: str | None = None,
        client: Any = None,
        model: str | None = None,
        provider: str | None = None,
        max_tool_rounds: int = 4,
    ) -> None:
        load_dotenv()
        self.conn = conn
        self.gate = gate
        self.incidents = incidents or IncidentStore(conn)
        self.fingerprint = fingerprint
        self.pcap_path = pcap_path
        self.max_tool_rounds = max_tool_rounds
        self.adapter = ProviderAdapter(
            role="defense",
            client=client,
            provider=provider or ("injected" if client is not None else None),
            model=model,
        )
        self.model = model

    def _run_tool(self, name: str, args: dict[str, Any], incident_id: str) -> dict[str, Any]:
        if name == "query_device_events":
            return query_device_events(
                self.conn,
                args["device_id"],
                limit=int(args.get("limit", 15)),
                audit=self.gate.audit,
                incidents=self.incidents,
                incident_id=incident_id,
            )
        if name == "device_deviation_report":
            return device_deviation_report(
                self.conn,
                args["device_id"],
                fingerprint=self.fingerprint,
                audit=self.gate.audit,
                incidents=self.incidents,
                incident_id=incident_id,
            )
        if name == "query_incident_history":
            return query_incident_history(
                self.conn,
                device_id=args.get("device_id"),
                limit=int(args.get("limit", 5)),
                audit=self.gate.audit,
            )
        if name == "extract_pcap_excerpt":
            return extract_pcap_excerpt(
                self.pcap_path,
                device_ip=args.get("device_ip"),
                audit=self.gate.audit,
                incidents=self.incidents,
                incident_id=incident_id,
            )
        return {"error": f"unknown tool {name!r}"}

    def _record_mode(self, incident_id: str, *, mode: str, error: str | None) -> None:
        """Persist mode/provider/model on the incident timeline for A/B evidence."""
        status = self.adapter.status()
        self.incidents.append_event(
            incident_id,
            kind="llm_mode",
            actor="defense_agent",
            summary=(
                f"mode={mode} provider={status.provider} model={status.model or 'n/a'} "
                f"circuit={status.circuit}"
            ),
            details={
                "mode": mode,
                "provider": status.provider,
                "model": status.model,
                "circuit": status.circuit,
                "error": error,
            },
        )

    def _fallback_result(
        self, detection: dict[str, Any], *, error: str | None = None
    ) -> DefenseResult:
        inc, iso = fallback_investigate(
            self.conn,
            self.gate,
            self.incidents,
            detection,
            fingerprint=self.fingerprint,
        )
        self._record_mode(inc.id, mode="fallback", error=error)
        final_rec = self.incidents.get_record(inc.id) or inc
        status = self.adapter.status()
        return DefenseResult(
            mode="fallback",
            incident=final_rec,
            isolation=iso,
            error=error,
            provider=status.provider,
            model=status.model,
        )

    def investigate(self, detection: dict[str, Any]) -> DefenseResult:
        if not self.adapter.status().configured:
            return self._fallback_result(detection)

        status = self.adapter.status()
        device_id = str(detection.get("device_id") or "unknown")
        severity = str(detection.get("severity") or "medium").lower()
        if severity not in ("low", "medium", "high", "critical"):
            severity = "medium"
        detection_ref = str(detection.get("detection_ref") or detection.get("id") or "det-llm")

        inc = self.incidents.create_incident(
            device_id=device_id,
            severity=severity,
            detection_ref=detection_ref,
            initial_evidence=detection,
            gate=self.gate,
            actor="defense",
        )

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(detection, sort_keys=True)},
        ]

        try:
            content = ""
            for _ in range(self.max_tool_rounds):
                result = self.adapter.complete(
                    messages=messages,
                    tools=DEFENSE_TOOL_SCHEMAS,
                    tool_choice="auto",
                    temperature=0.1,
                )
                tool_calls = result.tool_calls
                if not tool_calls:
                    content = result.content
                    break

                messages.append(
                    {
                        "role": "assistant",
                        "content": result.content,
                        "tool_calls": tool_calls,
                    }
                )
                for tc in tool_calls:
                    function = tc["function"]
                    args = json.loads(function.get("arguments") or "{}")
                    tool_result = self._run_tool(function.get("name", ""), args, inc.id)
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.get("id", ""),
                            "content": json.dumps(tool_result, default=str),
                        }
                    )

            parsed = json.loads(content) if content.strip().startswith("{") else {}
            rec_action = parsed.get("recommended_action", "log_alert")
            summary = parsed.get("summary") or content[:240] or "LLM investigation complete"
            llm_sev = parsed.get("severity", severity)
            if llm_sev not in ("low", "medium", "high", "critical"):
                llm_sev = severity

            self.incidents.update_incident(
                inc.id,
                status="investigating",
                severity=llm_sev,
                reasoning_summary=summary,
                decision=rec_action,
            )

            iso: IsolationResult | None = None
            if rec_action == "isolate_device":
                iso = isolate_device(
                    self.conn,
                    self.gate,
                    device_id,
                    actor="defense",
                    reason=summary,
                    incident_id=inc.id,
                    incidents=self.incidents,
                )
            else:
                alert_decision = self.gate.authorize(
                    "defense", "log_alert", device_id, context={"incident_id": inc.id}
                )
                if alert_decision.allowed:
                    self.incidents.update_incident(inc.id, status="open", action="log_alert", outcome="logged")
                else:
                    self.incidents.append_event(
                        inc.id,
                        kind="policy_denied",
                        actor="defense",
                        summary=f"log_alert denied for {device_id}: {alert_decision.reason}",
                        details={"action": "log_alert", "reason": alert_decision.reason},
                    )

            self._record_mode(inc.id, mode="llm", error=None)
            final_rec = self.incidents.get_record(inc.id)
            assert final_rec is not None
            return DefenseResult(
                mode="llm",
                incident=final_rec,
                isolation=iso,
                provider=status.provider,
                model=status.model,
            )

        except Exception as exc:
            self.incidents.append_event(
                inc.id,
                kind="fallback_switch",
                actor="defense_agent",
                summary=f"LLM error ({exc}); switching to deterministic fallback",
            )
            return self._fallback_result(detection, error=str(exc))
