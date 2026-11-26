from __future__ import annotations

import sqlite3
from typing import Any

from src.incidents import IncidentStore
from src.policy import AuditLogger


def _audit_tool(
    audit: AuditLogger | None,
    tool_name: str,
    target: str,
    context: dict[str, Any] | None = None,
) -> None:
    if audit is not None:
        audit.record(
            actor="defense_tool",
            action=tool_name,
            target=target,
            verdict="ALLOW",
            reason="read-only evidence tool",
            context=context,
        )


def query_device_events(
    conn: sqlite3.Connection,
    device_id: str,
    *,
    limit: int = 25,
    since_utc: str | None = None,
    audit: AuditLogger | None = None,
    incidents: IncidentStore | None = None,
    incident_id: str | None = None,
) -> dict[str, Any]:
    """Read-only query of recent MQTT events for a device."""
    clauses = ["device_id = ?"]
    params: list[Any] = [device_id]
    if since_utc is not None:
        clauses.append("ts_utc >= ?")
        params.append(since_utc)
    params.append(limit)

    rows = conn.execute(
        f"SELECT ts_utc, device_id, device_type, topic, qos, payload_size, direction "
        f"FROM mqtt_events WHERE {' AND '.join(clauses)} "
        f"ORDER BY ts_utc DESC, id DESC LIMIT ?",
        params,
    ).fetchall()
    events = [dict(r) for r in rows]

    result = {
        "device_id": device_id,
        "count": len(events),
        "events": events,
    }
    _audit_tool(audit, "query_device_events", device_id, {"limit": limit, "count": len(events)})
    if incidents is not None and incident_id is not None:
        incidents.append_event(
            incident_id,
            kind="tool_call",
            actor="defense_tool",
            summary=f"Queried {len(events)} MQTT events for {device_id}",
            details={"tool": "query_device_events", "count": len(events)},
        )
    return result


def query_incident_history(
    conn: sqlite3.Connection,
    *,
    device_id: str | None = None,
    limit: int = 10,
    audit: AuditLogger | None = None,
) -> dict[str, Any]:
    """Read-only query of past incidents, optionally filtered by device_id."""
    store = IncidentStore(conn)
    items = store.list_incidents(device_id=device_id, limit=limit)
    _audit_tool(
        audit,
        "query_incident_history",
        device_id or "all",
        {"limit": limit, "count": len(items)},
    )
    return {"device_id": device_id, "count": len(items), "incidents": items}
