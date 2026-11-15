# src/storage/

Persistence layer (Checkpoint 1, task C1-T06).

Planned files:
- `db.py` — SQLite connection, schema (`mqtt_events`, later `incidents`,
  `audit_log`), UTC ISO8601 timestamps, indexes on `ts_utc` and `topic`
- `queries.py` — reusable query helpers used by evidence tools and dashboards

Everything stored here is later consumed by: the detection feature extractor,
the defense agent's evidence tools, and the dashboard.
