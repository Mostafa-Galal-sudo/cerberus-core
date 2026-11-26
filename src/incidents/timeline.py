from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from src.policy import PolicyGate
from src.storage.db import utc_now, write_lock

from .schema import VALID_SEVERITIES, VALID_STATUSES, IncidentEvent, IncidentRecord


class IncidentStore:
    """SQLite-backed store for incidents and their ordered evidence timelines."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def create_incident(
        self,
        device_id: str,
        severity: str,
        detection_ref: str,
        reasoning_summary: str = "",
        decision: str = "",
        action: str = "",
        outcome: str = "",
        status: str = "open",
        initial_evidence: dict[str, Any] | None = None,
        incident_id: str | None = None,
        *,
        gate: PolicyGate,
        actor: str,
    ) -> IncidentRecord:
        gate.require(
            actor,
            "open_incident",
            device_id,
            context={"detection_ref": detection_ref, "severity": severity},
        )
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity {severity!r}")
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid status {status!r}")

        now = utc_now()
        inc_id = incident_id or f"inc-{uuid.uuid4().hex[:12]}"
        record = IncidentRecord(
            id=inc_id,
            created_utc=now,
            updated_utc=now,
            device_id=device_id,
            severity=severity,
            status=status,
            detection_ref=detection_ref,
            reasoning_summary=reasoning_summary,
            decision=decision,
            action=action,
            outcome=outcome,
        )

        with write_lock():
            self.conn.execute(
                "INSERT INTO incidents "
                "(id, created_utc, updated_utc, device_id, severity, status, "
                "detection_ref, reasoning_summary, decision, action, outcome) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.id,
                    record.created_utc,
                    record.updated_utc,
                    record.device_id,
                    record.severity,
                    record.status,
                    record.detection_ref,
                    record.reasoning_summary,
                    record.decision,
                    record.action,
                    record.outcome,
                ),
            )
            self.conn.commit()

        self.append_event(
            inc_id,
            kind="detection",
            actor="detector",
            summary=f"Incident opened from {detection_ref} ({severity})",
            details=initial_evidence or {},
        )
        return self.get_record(inc_id)  # type: ignore[return-value]

    def append_event(
        self,
        incident_id: str,
        kind: str,
        actor: str,
        summary: str,
        details: dict[str, Any] | None = None,
    ) -> IncidentEvent:
        now = utc_now()
        payload = details or {}
        details_json = json.dumps(payload, sort_keys=True)

        with write_lock():
            cur = self.conn.execute(
                "INSERT INTO incident_events "
                "(incident_id, ts_utc, kind, actor, summary, details_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (incident_id, now, kind, actor, summary, details_json),
            )
            self.conn.execute(
                "UPDATE incidents SET updated_utc = ? WHERE id = ?",
                (now, incident_id),
            )
            self.conn.commit()
            row_id = cur.lastrowid

        return IncidentEvent(
            id=row_id,
            incident_id=incident_id,
            ts_utc=now,
            kind=kind,
            actor=actor,
            summary=summary,
            details=payload,
        )

    def update_incident(
        self,
        incident_id: str,
        *,
        status: str | None = None,
        severity: str | None = None,
        reasoning_summary: str | None = None,
        decision: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
    ) -> IncidentRecord:
        if status is not None and status not in VALID_STATUSES:
            raise ValueError(f"invalid status {status!r}")
        if severity is not None and severity not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity {severity!r}")

        updates: list[str] = ["updated_utc = ?"]
        params: list[Any] = [utc_now()]

        for col, val in (
            ("status", status),
            ("severity", severity),
            ("reasoning_summary", reasoning_summary),
            ("decision", decision),
            ("action", action),
            ("outcome", outcome),
        ):
            if val is not None:
                updates.append(f"{col} = ?")
                params.append(val)

        params.append(incident_id)
        with write_lock():
            cur = self.conn.execute(
                f"UPDATE incidents SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            self.conn.commit()
            if cur.rowcount == 0:
                raise KeyError(f"incident {incident_id!r} not found")

        rec = self.get_record(incident_id)
        assert rec is not None
        return rec

    def get_timeline(self, incident_id: str) -> list[IncidentEvent]:
        rows = self.conn.execute(
            "SELECT id, incident_id, ts_utc, kind, actor, summary, details_json "
            "FROM incident_events WHERE incident_id = ? ORDER BY ts_utc ASC, id ASC",
            (incident_id,),
        ).fetchall()
        events: list[IncidentEvent] = []
        for row in rows:
            events.append(
                IncidentEvent(
                    id=row["id"],
                    incident_id=row["incident_id"],
                    ts_utc=row["ts_utc"],
                    kind=row["kind"],
                    actor=row["actor"],
                    summary=row["summary"],
                    details=json.loads(row["details_json"]) if row["details_json"] else {},
                )
            )
        return events

    def get_record(self, incident_id: str) -> IncidentRecord | None:
        row = self.conn.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        if row is None:
            return None
        return IncidentRecord(
            id=row["id"],
            created_utc=row["created_utc"],
            updated_utc=row["updated_utc"],
            device_id=row["device_id"],
            severity=row["severity"],
            status=row["status"],
            detection_ref=row["detection_ref"],
            reasoning_summary=row["reasoning_summary"] or "",
            decision=row["decision"] or "",
            action=row["action"] or "",
            outcome=row["outcome"] or "",
            timeline=self.get_timeline(incident_id),
        )

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        rec = self.get_record(incident_id)
        return rec.to_dict() if rec is not None else None

    def list_incidents(
        self,
        *,
        status: str | None = None,
        device_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if device_id is not None:
            clauses.append("device_id = ?")
            params.append(device_id)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self.conn.execute(
            f"SELECT * FROM incidents {where} ORDER BY created_utc DESC LIMIT ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]
