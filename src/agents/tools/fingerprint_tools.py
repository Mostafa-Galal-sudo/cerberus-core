from __future__ import annotations

import sqlite3
from typing import Any

from src.detection.features import device_windows
from src.detection.fingerprint import DeviceFingerprint
from src.incidents import IncidentStore
from src.policy import AuditLogger


def device_deviation_report(
    conn: sqlite3.Connection,
    device_id: str,
    *,
    fingerprint: DeviceFingerprint | None = None,
    window_sec: int = 60,
    audit: AuditLogger | None = None,
    incidents: IncidentStore | None = None,
    incident_id: str | None = None,
) -> dict[str, Any]:
    """Compute a read-only per-device behavioral deviation report from recent windows."""
    windows = [w for w in device_windows(conn, window_sec=window_sec) if w["device_id"] == device_id]

    if not windows:
        report: dict[str, Any] = {
            "device_id": device_id,
            "known_device": bool(fingerprint.known(device_id)) if fingerprint else False,
            "windows_analyzed": 0,
            "max_score": 0.0,
            "anomalous_windows": 0,
            "top_drivers": [],
        }
    elif fingerprint is not None and fingerprint.global_ is not None:
        preds, scores, drivers = fingerprint.predict(windows)
        flat_drivers: list[str] = []
        for drv in drivers:
            for name in drv:
                if name not in flat_drivers:
                    flat_drivers.append(name)
        report = {
            "device_id": device_id,
            "known_device": bool(fingerprint.known(device_id)),
            "windows_analyzed": len(windows),
            "max_score": round(float(max(scores)), 3),
            "threshold": round(float(fingerprint.threshold_), 3),
            "anomalous_windows": int(sum(int(p) for p in preds)),
            "top_drivers": flat_drivers[:5],
        }
    else:
        latest = windows[-1]
        report = {
            "device_id": device_id,
            "known_device": False,
            "windows_analyzed": len(windows),
            "latest_rate_per_sec": round(float(latest["rate_per_sec"]), 3),
            "latest_payload_mean": round(float(latest["payload_mean"]), 2),
            "latest_topic_entropy": round(float(latest["topic_entropy"]), 3),
        }

    if audit is not None:
        audit.record(
            actor="defense_tool",
            action="device_deviation_report",
            target=device_id,
            verdict="ALLOW",
            reason="read-only fingerprint inspection",
            context={"windows_analyzed": report["windows_analyzed"]},
        )
    if incidents is not None and incident_id is not None:
        incidents.append_event(
            incident_id,
            kind="tool_call",
            actor="defense_tool",
            summary=f"Fingerprint report for {device_id} ({report['windows_analyzed']} windows)",
            details=report,
        )
    return report
