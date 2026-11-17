from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

_WRITE_LOCK = threading.Lock()

SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS mqtt_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc          TEXT    NOT NULL,
    device_id       TEXT    NOT NULL,
    device_type     TEXT    NOT NULL,
    topic           TEXT    NOT NULL,
    qos             INTEGER NOT NULL,
    payload_size    INTEGER NOT NULL,
    payload_preview TEXT,
    direction       TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts    ON mqtt_events (ts_utc);
CREATE INDEX IF NOT EXISTS idx_events_topic ON mqtt_events (topic);
CREATE INDEX IF NOT EXISTS idx_events_dev   ON mqtt_events (device_id);
"""


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def open_db(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def save_event(conn, ev):
    with _WRITE_LOCK:
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
