from __future__ import annotations

import sqlite3
from typing import Any

from src.agents.tools import device_deviation_report, query_device_events
from src.detection.fingerprint import DeviceFingerprint
from src.incidents import IncidentRecord, IncidentStore
from src.policy import PolicyGate
from src.response import IsolationResult, isolate_device


def fallback_investigate(
    conn: sqlite3.Connection,
    gate: PolicyGate,
    incidents: IncidentStore,
    detection: dict[str, Any],
    *,
    fingerprint: DeviceFingerprint | None = None,
    auto_isolate_severities: tuple[str, ...] = ("high", "critical"),
) -> tuple[IncidentRecord, IsolationResult | None]:
    """Deterministic rules-only investigation + policy-bounded response when LLMs are unavailable."""
    device_id = str(detection.get("device_id") or "unknown")
    severity = str(detection.get("severity") or "medium").lower()
    if severity not in ("low", "medium", "high", "critical"):
        severity = "medium"
    detection_ref = str(detection.get("detection_ref") or detection.get("id") or "det-fallback")
    explanation = str(detection.get("explanation") or "deterministic rule trigger")

    inc = incidents.create_incident(
        device_id=device_id,
        severity=severity,
        detection_ref=detection_ref,
        initial_evidence=detection,
    )

    ev_report = query_device_events(
        conn,
        device_id,
        limit=10,
        audit=gate.audit,
        incidents=incidents,
        incident_id=inc.id,
    )
    fp_report = device_deviation_report(
        conn,
        device_id,
        fingerprint=fingerprint,
        audit=gate.audit,
        incidents=incidents,
        incident_id=inc.id,
    )

    should_isolate = severity in auto_isolate_severities
    recommended_action = "isolate_device" if should_isolate else "log_alert"
    summary = (
        f"[fallback] {explanation}; events={ev_report['count']}, "
        f"windows={fp_report['windows_analyzed']}"
    )

    incidents.update_incident(
        inc.id,
        status="investigating",
        reasoning_summary=summary,
        decision=recommended_action,
    )

    iso_result: IsolationResult | None = None
    if should_isolate:
        iso_result = isolate_device(
            conn,
            gate,
            device_id,
            actor="defense",
            reason=f"fallback auto-isolation: {explanation}",
            incident_id=inc.id,
            incidents=incidents,
        )
    else:
        gate.authorize("defense", "log_alert", device_id, context={"incident_id": inc.id})
        incidents.update_incident(
            inc.id,
            status="open",
            action="log_alert",
            outcome="logged",
        )

    final_rec = incidents.get_record(inc.id)
    assert final_rec is not None
    return final_rec, iso_result


def fallback_attack_plan(
    target_device: str = "esp32_temp_01",
    attack_kind: str = "attack_flood",
) -> dict[str, Any]:
    """Deterministic attack proposal when DeepSeek API is unavailable."""
    valid_kinds = ("attack_flood", "attack_bloat", "attack_rogue", "attack_spoof")
    action = attack_kind if attack_kind in valid_kinds else "attack_flood"
    return {
        "mode": "fallback",
        "action": action,
        "target": target_device,
        "reason": "deterministic fallback attack scenario",
    }
