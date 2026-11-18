"""Groq-powered defense agent — alert investigation and confirmed response.

Reads alerts/devices from the SOC database, correlates related alerts into
incidents, and — only through the policy-bounded response layer — isolates
confirmed malicious endpoints. The agent itself never touches device state
directly: every isolation goes through agents/response.execute_isolation,
which enforces protected targets, confidence thresholds, and rate bounds.

The LLM client is any OpenAI-SDK-shaped object; the real Groq client
(base_url https://api.groq.com/openai/v1) is created lazily so tests never
need it.
"""
from __future__ import annotations

from typing import Any

import config
from agents.response import IsolationDenied, execute_isolation
from agents.scaffold import LLMAgent, RateLimiter, ScopePolicy, ToolSpec

GROQ_BASE_URL = "https://api.groq.com/openai/v1"

_SYSTEM_PROMPT = """\
You are CERBERUS's defense agent (SOC analyst). Investigate alerts, correlate
related ones into incidents, and recommend actions. You may isolate a device
ONLY when the alert evidence clearly supports it — isolation requests pass
through a strict policy layer that will refuse weak or protected targets.
Always cite alert ids and confidence when deciding. Be concise and evidence-
driven; never invent data you did not retrieve with a tool."""


class DefenseTools:
    """Tool handlers for the defense agent (kept free of LLM specifics)."""

    def __init__(self, db: Any, scope: ScopePolicy | None = None):
        self.db = db
        self.scope = scope or ScopePolicy()

    # -- investigation tools ----------------------------------------------------
    def get_alert_details(self, alert_id: int) -> dict:
        alert = self.db.get_alert(int(alert_id))
        if alert is None:
            return {"error": f"alert {alert_id} not found"}
        # Drop the raw feature blob from the LLM context (too large, not needed).
        return {k: v for k, v in alert.items() if k != "features"}

    def list_open_alerts(self, limit: int = 20) -> dict:
        alerts = self.db.list_alerts(status="open", limit=min(int(limit), 100))
        summary = [
            {
                "id": a["id"],
                "device_id": a["device_id"],
                "attack_class": a["attack_class"],
                "confidence": a["confidence"],
                "created_at": a["created_at"],
            }
            for a in alerts
        ]
        return {"open_alerts": summary, "count": len(summary)}

    def correlate_alerts(self, alert_ids: list[int] | None = None) -> dict:
        """Group alerts by (device, attack class) to reveal multi-alert campaigns."""
        if alert_ids:
            alerts = [a for a in (self.db.get_alert(int(i)) for i in alert_ids)
                      if a is not None]
        else:
            alerts = self.db.list_alerts(limit=100)
        clusters: dict[tuple, list[dict]] = {}
        for alert in alerts:
            key = (alert.get("device_id") or "unknown",
                   alert.get("attack_class") or "unknown")
            clusters.setdefault(key, []).append(alert)
        correlated = []
        for (device_id, attack_class), group in sorted(clusters.items()):
            confidences = [a["confidence"] or 0.0 for a in group]
            correlated.append({
                "device_id": device_id,
                "attack_class": attack_class,
                "alert_count": len(group),
                "alert_ids": [a["id"] for a in group],
                "avg_confidence": round(sum(confidences) / len(confidences), 3),
                "first_seen": min(a["created_at"] for a in group),
                "last_seen": max(a["created_at"] for a in group),
            })
        correlated.sort(key=lambda c: (-c["alert_count"], -c["avg_confidence"]))
        return {"clusters": correlated}

    # -- incident management ------------------------------------------------------
    def create_incident(self, title: str, alert_ids: list[int] | None = None) -> dict:
        incident_id = self.db.create_incident(str(title), [int(i) for i in alert_ids or []])
        self.db.append_event(incident_id, "investigation",
                             f"Incident opened by defense agent: {title}")
        self.db.audit("defense-agent", "incident_created",
                      {"incident_id": incident_id, "title": title,
                       "alert_ids": alert_ids or []})
        return {"incident_id": incident_id, "title": title,
                "alert_ids": alert_ids or []}

    def append_timeline_event(self, incident_id: int, event_type: str,
                              message: str) -> dict:
        event_id = self.db.append_event(int(incident_id), str(event_type),
                                        str(message))
        if event_id is None:
            return {"error": f"incident {incident_id} not found"}
        return {"event_id": event_id, "incident_id": int(incident_id)}

    # -- response (policy-bounded) -------------------------------------------------
    def request_isolation(self, device_id: str, alert_id: int,
                          incident_id: int | None = None,
                          reason: str = "") -> dict:
        """Confirmed-verdict isolation. Delegates to the response policy."""
        self.scope.check(device_id)
        try:
            return execute_isolation(
                self.db, str(device_id),
                alert_id=int(alert_id),
                incident_id=int(incident_id) if incident_id is not None else None,
                confirmed_by="defense-agent",
                reason=str(reason),
            )
        except IsolationDenied as exc:
            return {"denied": True, "reason": str(exc)}


def build_defense_tools(**kwargs: Any) -> dict[str, ToolSpec]:
    tools = DefenseTools(**kwargs)
    return {
        "get_alert_details": ToolSpec(
            name="get_alert_details",
            description="Fetch one alert's full record: scores, rule hits, "
                        "SHAP explanation, and reasons.",
            parameters={
                "type": "object",
                "properties": {"alert_id": {"type": "integer"}},
                "required": ["alert_id"],
            },
            handler=tools.get_alert_details,
        ),
        "list_open_alerts": ToolSpec(
            name="list_open_alerts",
            description="List currently open alerts (id, device, class, "
                        "confidence, time).",
            parameters={
                "type": "object",
                "properties": {"limit": {"type": "integer", "minimum": 1,
                                         "maximum": 100}},
            },
            handler=tools.list_open_alerts,
        ),
        "correlate_alerts": ToolSpec(
            name="correlate_alerts",
            description="Cluster alerts by device and attack class to reveal "
                        "multi-alert campaigns; returns per-cluster stats.",
            parameters={
                "type": "object",
                "properties": {
                    "alert_ids": {
                        "type": "array", "items": {"type": "integer"},
                        "description": "Optional subset to correlate",
                    },
                },
            },
            handler=tools.correlate_alerts,
        ),
        "create_incident": ToolSpec(
            name="create_incident",
            description="Open an investigation incident linking related "
                        "alerts.",
            parameters={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "alert_ids": {"type": "array", "items": {"type": "integer"}},
                },
                "required": ["title"],
            },
            handler=tools.create_incident,
            rate_limit=RateLimiter(min_interval=1.0, max_per_window=20,
                                   window_seconds=60.0),
        ),
        "append_timeline_event": ToolSpec(
            name="append_timeline_event",
            description="Append an event (detection/investigation/response) "
                        "to an incident timeline.",
            parameters={
                "type": "object",
                "properties": {
                    "incident_id": {"type": "integer"},
                    "event_type": {"type": "string"},
                    "message": {"type": "string"},
                },
                "required": ["incident_id", "event_type", "message"],
            },
            handler=tools.append_timeline_event,
        ),
        "request_isolation": ToolSpec(
            name="request_isolation",
            description="Isolate a device after a confirmed verdict. Passes "
                        "through the response policy: protected devices and "
                        "low-confidence alerts are refused.",
            parameters={
                "type": "object",
                "properties": {
                    "device_id": {"type": "string"},
                    "alert_id": {"type": "integer"},
                    "incident_id": {"type": "integer"},
                    "reason": {"type": "string"},
                },
                "required": ["device_id", "alert_id"],
            },
            handler=tools.request_isolation,
            scope_arg="device_id",
            rate_limit=RateLimiter(min_interval=5.0, max_per_window=5,
                                   window_seconds=60.0),
        ),
    }


def build_defense_agent(
    client: Any = None,
    model: str | None = None,
    **tool_kwargs: Any,
) -> LLMAgent:
    """Assemble the Groq defense agent. `client=None` builds the real one."""
    if client is None:
        from openai import OpenAI  # lazy: only real runs need the SDK

        client = OpenAI(base_url=GROQ_BASE_URL, api_key=config.GROQ_API_KEY)
    return LLMAgent(
        client=client,
        model=model or config.GROQ_MODEL,
        system_prompt=_SYSTEM_PROMPT,
        tools=build_defense_tools(**tool_kwargs),
    )
