"""SQLite persistence layer for CERBERUS.

Plain sqlite3 (no ORM dependency). One connection per operation with WAL
mode; JSON columns are stored as TEXT and parsed on read.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

JSON_COLUMNS = {
    "alerts": ("rule_hits", "reasons", "ml_top_features", "explanation", "features"),
    "devices": ("meta",),
    "incidents": ("alert_ids",),
    "incident_events": (),
    "audit_log": ("detail",),
}

ALERT_STATUSES = ("open", "acknowledged", "resolved", "false_positive")
DEVICE_STATUSES = ("trusted", "suspicious", "isolated")

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    device_id TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'trusted',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    meta TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    device_id TEXT,
    source_label TEXT,
    attack_class TEXT,
    is_attack INTEGER,
    anomaly_score REAL,
    rule_score REAL,
    fingerprint_score REAL,
    fused_score REAL,
    confidence REAL,
    rule_hits TEXT NOT NULL DEFAULT '[]',
    reasons TEXT NOT NULL DEFAULT '[]',
    ml_top_features TEXT,
    explanation TEXT,
    features TEXT,
    status TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    alert_ids TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS incident_events (
    id INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    created_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_incident ON incident_events(incident_id);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self) -> Database:
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
        return self

    # -- helpers ------------------------------------------------------------
    def _decode(self, table: str, row: sqlite3.Row) -> dict:
        record = dict(row)
        for col in JSON_COLUMNS.get(table, ()):
            if record.get(col) is not None:
                record[col] = json.loads(record[col])
        return record

    @staticmethod
    def _encode(value: object) -> str | None:
        return None if value is None else json.dumps(value)

    # -- alerts -------------------------------------------------------------
    def insert_alert(self, **fields: object) -> int:
        allowed = {
            "device_id", "source_label", "attack_class", "is_attack",
            "anomaly_score", "rule_score", "fingerprint_score", "fused_score",
            "confidence", "rule_hits", "reasons", "ml_top_features",
            "explanation", "features", "status",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"Unknown alert fields: {sorted(unknown)}")
        fields.setdefault("created_at", _now())
        encoded = {k: self._encode(v) if k in JSON_COLUMNS["alerts"] else v
                   for k, v in fields.items()}
        cols = ", ".join(encoded)
        placeholders = ", ".join("?" for _ in encoded)
        with self._conn() as conn:
            cur = conn.execute(
                f"INSERT INTO alerts ({cols}) VALUES ({placeholders})",
                list(encoded.values()),
            )
            return int(cur.lastrowid)

    def get_alert(self, alert_id: int) -> dict | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            return self._decode("alerts", row) if row else None

    def list_alerts(self, status: str | None = None, limit: int = 100) -> list[dict]:
        query = "SELECT * FROM alerts"
        params: tuple = ()
        if status is not None:
            query += " WHERE status = ?"
            params = (status,)
        query += " ORDER BY id DESC LIMIT ?"
        with self._conn() as conn:
            rows = conn.execute(query, (*params, limit)).fetchall()
            return [self._decode("alerts", r) for r in rows]

    def set_alert_status(self, alert_id: int, status: str) -> bool:
        if status not in ALERT_STATUSES:
            raise ValueError(f"status must be one of {ALERT_STATUSES}")
        with self._conn() as conn:
            cur = conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
            return cur.rowcount > 0

    # -- devices ------------------------------------------------------------
    def upsert_device(self, device_id: str, meta: dict | None = None) -> None:
        now = _now()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO devices (device_id, first_seen, last_seen, meta)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(device_id) DO UPDATE SET last_seen = excluded.last_seen""",
                (device_id, now, now, self._encode(meta or {})),
            )

    def list_devices(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM devices ORDER BY device_id").fetchall()
            return [self._decode("devices", r) for r in rows]

    def set_device_status(self, device_id: str, status: str) -> bool:
        if status not in DEVICE_STATUSES:
            raise ValueError(f"status must be one of {DEVICE_STATUSES}")
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE devices SET status = ? WHERE device_id = ?", (status, device_id),
            )
            return cur.rowcount > 0

    # -- incidents ----------------------------------------------------------
    def create_incident(self, title: str, alert_ids: list[int] | None = None) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO incidents (created_at, title, alert_ids) VALUES (?, ?, ?)",
                (_now(), title, self._encode(alert_ids or [])),
            )
            return int(cur.lastrowid)

    def get_incident(self, incident_id: int) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,),
            ).fetchone()
            return self._decode("incidents", row) if row else None

    def list_incidents(self, limit: int = 100) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,),
            ).fetchall()
            return [self._decode("incidents", r) for r in rows]

    def append_event(self, incident_id: int, event_type: str, message: str) -> int | None:
        with self._conn() as conn:
            exists = conn.execute(
                "SELECT 1 FROM incidents WHERE id = ?", (incident_id,),
            ).fetchone()
            if not exists:
                return None
            cur = conn.execute(
                "INSERT INTO incident_events (incident_id, created_at, event_type, message)"
                " VALUES (?, ?, ?, ?)",
                (incident_id, _now(), event_type, message),
            )
            return int(cur.lastrowid)

    def get_timeline(self, incident_id: int) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM incident_events WHERE incident_id = ? ORDER BY id",
                (incident_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    # -- audit --------------------------------------------------------------
    def audit(self, actor: str, action: str, detail: dict | None = None) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO audit_log (ts, actor, action, detail) VALUES (?, ?, ?, ?)",
                (_now(), actor, action, self._encode(detail or {})),
            )
            return int(cur.lastrowid)

    def list_audit(self, limit: int = 100) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,),
            ).fetchall()
            return [self._decode("audit_log", r) for r in rows]
