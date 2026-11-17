"""SQLite persistence layer for CERBERUS (Checkpoint 1, task C1-T06).

Stores every MQTT event produced by the simulator with UTC timestamps.
Later layers consume this database:
  - detection feature extractor  (Checkpoint 2)
  - defense agent evidence tools (Checkpoint 3)
  - dashboard                    (Checkpoint 3+)

All timestamps are ISO8601 UTC strings so that lab data (Checkpoint 4) and
CICIoT2023-derived tables stay comparable.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS mqtt_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc          TEXT    NOT NULL,            -- ISO8601 UTC
    device_id       TEXT    NOT NULL,
    device_type     TEXT    NOT NULL,
    topic           TEXT    NOT NULL,
    qos             INTEGER NOT NULL,
    payload_size    INTEGER NOT NULL,            -- bytes
    payload_preview TEXT,                        -- first 120 bytes, for evidence
    direction       TEXT    NOT NULL             -- 'publish' | 'subscribe'
);

CREATE INDEX IF NOT EXISTS idx_events_ts    ON mqtt_events (ts_utc);
CREATE INDEX IF NOT EXISTS idx_events_topic ON mqtt_events (topic);
CREATE INDEX IF NOT EXISTS idx_events_dev   ON mqtt_events (device_id);
"""


def utc_now_iso() -> str:
    """Current time as an ISO8601 UTC string (the project-wide timestamp format)."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open (and create) the database, applying the schema."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def insert_event(conn: sqlite3.Connection, ev: dict) -> None:
    """Insert one MQTT event record."""
    conn.execute(
        "INSERT INTO mqtt_events "
        "(ts_utc, device_id, device_type, topic, qos, payload_size, payload_preview, direction) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            ev["ts_utc"],
            ev["device_id"],
            ev["device_type"],
            ev["topic"],
            ev["qos"],
            ev["payload_size"],
            ev["payload_preview"],
            ev["direction"],
        ),
    )
    conn.commit()


def event_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM mqtt_events").fetchone()[0]


def summary(conn: sqlite3.Connection) -> dict:
    """Aggregated stats for the demo / evidence pack (task C1-T10)."""
    return {
        "total_events": event_count(conn),
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
