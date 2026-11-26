from __future__ import annotations

import json
import os
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

DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"

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


class DefenseAgent:
    """Groq-powered defense agent with tool-calling and deterministic fallback."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        gate: PolicyGate,
        incidents: IncidentStore | None = None,
        *,
        fingerprint: DeviceFingerprint | None = None,
        pcap_path: str | None = None,
        client: Any = None,
        model: str = DEFAULT_GROQ_MODEL,
        max_tool_rounds: int = 4,
    ) -> None:
        load_dotenv()
        self.conn = conn
        self.gate = gate
        self.incidents = incidents or IncidentStore(conn)
        self.fingerprint = fingerprint
        self.pcap_path = pcap_path
        self.model = model
        self.max_tool_rounds = max_tool_rounds
        self._client = client

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            return None
        from groq import Groq

        self._client = Groq(api_key=api_key)
        return self._client

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

    def investigate(self, detection: dict[str, Any]) -> DefenseResult:
        client = self._get_client()
        if client is None:
            inc, iso = fallback_investigate(
                self.conn,
                self.gate,
                self.incidents,
                detection,
                fingerprint=self.fingerprint,
            )
            return DefenseResult(mode="fallback", incident=inc, isolation=iso)

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
        )

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(detection, sort_keys=True)},
        ]

        try:
            content = ""
            for _ in range(self.max_tool_rounds):
                resp = client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    tools=DEFENSE_TOOL_SCHEMAS,
                    tool_choice="auto",
                    temperature=0.1,
                )
                msg = resp.choices[0].message
                tool_calls = getattr(msg, "tool_calls", None) or []
                if not tool_calls:
                    content = msg.content or ""
                    break

                messages.append(
                    {
                        "role": "assistant",
                        "content": msg.content or "",
                        "tool_calls": [
                            {
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.function.name,
                                    "arguments": tc.function.arguments,
                                },
                            }
                            for tc in tool_calls
                        ],
                    }
                )
                for tc in tool_calls:
                    args = json.loads(tc.function.arguments or "{}")
                    result = self._run_tool(tc.function.name, args, inc.id)
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": json.dumps(result, default=str),
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
                self.gate.authorize("defense", "log_alert", device_id, context={"incident_id": inc.id})
                self.incidents.update_incident(inc.id, status="open", action="log_alert", outcome="logged")

            final_rec = self.incidents.get_record(inc.id)
            assert final_rec is not None
            return DefenseResult(mode="llm", incident=final_rec, isolation=iso)

        except Exception as exc:
            self.incidents.append_event(
                inc.id,
                kind="fallback_switch",
                actor="defense_agent",
                summary=f"LLM error ({exc}); switching to deterministic fallback",
            )
            fb_inc, fb_iso = fallback_investigate(
                self.conn,
                self.gate,
                self.incidents,
                detection,
                fingerprint=self.fingerprint,
            )
            return DefenseResult(mode="fallback", incident=fb_inc, isolation=fb_iso, error=str(exc))
