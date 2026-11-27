from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

_WRITE_LOCK = threading.Lock()
DEFAULT_DB_PATH = Path("data/lab/lab_traffic.db")

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS mqtt_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc          TEXT    NOT NULL,
    device_id       TEXT    NOT NULL,
    device_type     TEXT    NOT NULL,
    topic           TEXT    NOT NULL,
    qos             INTEGER NOT NULL,
    payload_size    INTEGER NOT NULL,
    payload_preview TEXT,
    direction       TEXT    NOT NULL,
    correlation_id  TEXT,
    injector_id     TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts    ON mqtt_events (ts_utc);
CREATE INDEX IF NOT EXISTS idx_events_topic ON mqtt_events (topic);
CREATE INDEX IF NOT EXISTS idx_events_dev   ON mqtt_events (device_id);

CREATE TABLE IF NOT EXISTS policy_audit (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc       TEXT    NOT NULL,
    actor        TEXT    NOT NULL,
    action       TEXT    NOT NULL,
    target       TEXT    NOT NULL,
    verdict      TEXT    NOT NULL,
    reason       TEXT    NOT NULL,
    context_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts    ON policy_audit (ts_utc);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON policy_audit (actor, action);

CREATE TABLE IF NOT EXISTS incidents (
    id                TEXT PRIMARY KEY,
    created_utc       TEXT NOT NULL,
    updated_utc       TEXT NOT NULL,
    device_id         TEXT NOT NULL,
    severity          TEXT NOT NULL,
    status            TEXT NOT NULL,
    detection_ref     TEXT NOT NULL,
    reasoning_summary TEXT,
    decision          TEXT,
    action            TEXT,
    outcome           TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status  ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_device  ON incidents (device_id);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents (created_utc);

CREATE TABLE IF NOT EXISTS incident_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  TEXT    NOT NULL,
    ts_utc       TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    actor        TEXT    NOT NULL,
    summary      TEXT    NOT NULL,
    details_json TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_inc_events_inc ON incident_events (incident_id, ts_utc);

CREATE TABLE IF NOT EXISTS isolations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    TEXT NOT NULL,
    status       TEXT NOT NULL,
    reason       TEXT NOT NULL,
    actor        TEXT NOT NULL,
    started_utc  TEXT NOT NULL,
    expires_utc  TEXT,
    released_utc TEXT,
    incident_id  TEXT
);

CREATE INDEX IF NOT EXISTS idx_isolations_dev ON isolations (device_id, status);
"""


def get_db_path(override: str | Path | None = None) -> Path:
    if override is not None:
        return Path(override)
    env_path = os.environ.get("CERBERUS_DB_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_DB_PATH


def write_lock() -> threading.Lock:
    return _WRITE_LOCK


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def open_db(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # E1 runs subscriber, injector, worker and dashboard in separate processes.
    # A 30s busy timeout serializes writers instead of failing under contention.
    conn = sqlite3.connect(path, timeout=30.0, check_same_thread=False)
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    # E2 adds correlation metadata. Existing lab DBs must remain readable.
    columns = {row[1] for row in conn.execute("PRAGMA table_info(mqtt_events)")}
    for column in ("correlation_id", "injector_id"):
        if column not in columns:
            conn.execute(f"ALTER TABLE mqtt_events ADD COLUMN {column} TEXT")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_corr ON mqtt_events (correlation_id)"
    )
    conn.commit()
    return conn


def save_event(conn, ev):
    with _WRITE_LOCK:
        conn.execute(
            "INSERT INTO mqtt_events "
            "(ts_utc, device_id, device_type, topic, qos, payload_size, payload_preview, "
            "direction, correlation_id, injector_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ev["ts_utc"],
                ev["device_id"],
                ev["device_type"],
                ev["topic"],
                ev["qos"],
                ev["payload_size"],
                ev["payload_preview"],
                ev["direction"],
                ev.get("correlation_id"),
                ev.get("injector_id"),
            ),
        )
        conn.commit()


def total_events(conn):
    return conn.execute("SELECT COUNT(*) FROM mqtt_events").fetchone()[0]


def summarize(conn):
    return {
        "total_events": total_events(conn),
        "per_device": [
            dict(r)
            for r in conn.execute(
                "SELECT device_id, device_type, COUNT(*) AS events, "
                "AVG(payload_size) AS avg_payload_bytes "
                "FROM mqtt_events GROUP BY device_id ORDER BY device_id"
            )
        ],
        "per_topic": [
            dict(r)
            for r in conn.execute(
                "SELECT topic, direction, COUNT(*) AS events "
                "FROM mqtt_events GROUP BY topic, direction ORDER BY topic"
            )
        ],
        "events_per_minute": [
            dict(r)
            for r in conn.execute(
                "SELECT strftime('%Y-%m-%dT%H:%M', ts_utc) AS minute, COUNT(*) AS events "
                "FROM mqtt_events GROUP BY minute ORDER BY minute"
            )
        ],
    }
