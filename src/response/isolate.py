from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from src.incidents import IncidentStore
from src.policy import PolicyDecision, PolicyGate

from .registry import IsolationRecord, IsolationRegistry


@dataclass(frozen=True)
class IsolationResult:
    executed: bool
    decision: PolicyDecision
    record: IsolationRecord | None = None


def isolate_device(
    conn: sqlite3.Connection,
    gate: PolicyGate,
    device_id: str,
    *,
    actor: str = "defense",
    reason: str = "confirmed anomaly",
    ttl_sec: int | None = 300,
    incident_id: str | None = None,
    incidents: IncidentStore | None = None,
    context: dict[str, Any] | None = None,
) -> IsolationResult:
    """Policy-bounded simulated device isolation (C3)."""
    decision = gate.authorize(actor, "isolate_device", device_id, context=context)
    if not decision.allowed:
        if incidents is not None and incident_id is not None:
            incidents.append_event(
                incident_id,
                kind="policy_denied",
                actor=actor,
                summary=f"Isolation denied for {device_id}: {decision.reason}",
                details={"action": "isolate_device", "reason": decision.reason},
            )
        return IsolationResult(executed=False, decision=decision, record=None)

    registry = IsolationRegistry(conn)
    record = registry.activate(
        device_id,
        reason=reason,
        actor=actor,
        ttl_sec=ttl_sec,
        incident_id=incident_id,
    )
    if incidents is not None and incident_id is not None:
        incidents.append_event(
            incident_id,
            kind="isolation",
            actor=actor,
            summary=f"Isolated {device_id} (ttl={ttl_sec}s): {reason}",
            details=record.to_dict(),
        )
        incidents.update_incident(
            incident_id,
            status="mitigated",
            action="isolate_device",
            outcome="isolated",
        )
    return IsolationResult(executed=True, decision=decision, record=record)


def release_device(
    conn: sqlite3.Connection,
    gate: PolicyGate,
    device_id: str,
    *,
    actor: str = "operator",
    reason: str = "manual step-down",
    incident_id: str | None = None,
    incidents: IncidentStore | None = None,
    context: dict[str, Any] | None = None,
) -> IsolationResult:
    """Policy-bounded release / step-down of an isolated device."""
    decision = gate.authorize(actor, "release_device", device_id, context=context)
    if not decision.allowed:
        return IsolationResult(executed=False, decision=decision, record=None)

    registry = IsolationRegistry(conn)
    released_count = registry.release(device_id)
    if incidents is not None and incident_id is not None:
        incidents.append_event(
            incident_id,
            kind="release",
            actor=actor,
            summary=f"Released {device_id} ({released_count} active record(s)): {reason}",
            details={"released_count": released_count, "reason": reason},
        )
        if released_count > 0:
            incidents.update_incident(incident_id, status="resolved", outcome="released")
    return IsolationResult(executed=released_count > 0, decision=decision, record=None)
