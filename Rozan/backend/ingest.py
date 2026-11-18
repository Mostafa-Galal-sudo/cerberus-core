"""Adapter: detection engine output -> alert records in SQLite.

Bridges the detection layer and the backend without either depending on the
other. Scoring frames are persisted alongside their alert records so alerts
remain reproducible/investigable later.
"""
from __future__ import annotations

import pandas as pd

from backend.db import Database
from detection.schema import (
    CATEGORY_COLUMN,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
)

_ALERT_NUMBERS = ("anomaly_score", "rule_score", "fingerprint_score",
                  "fused_score", "confidence")


def alerts_to_records(df: pd.DataFrame, alerts: pd.DataFrame) -> list[dict]:
    """Convert an engine score() result plus its traffic frame to DB records."""
    records = []
    for idx, alert in alerts.iterrows():
        row = df.loc[idx] if idx in df.index else None
        record = {
            "device_id": str(row["device_id"]) if row is not None and "device_id" in row else None,
            "source_label": str(row[LABEL_COLUMN]) if row is not None and LABEL_COLUMN in row else None,
            "attack_class": str(row[CATEGORY_COLUMN]) if row is not None and CATEGORY_COLUMN in row else None,
            "is_attack": int(row["is_attack"]) if row is not None and "is_attack" in row else None,
            "rule_hits": list(alert.get("rule_hits") or []),
            "reasons": list(alert.get("reasons") or []),
            "ml_top_features": alert.get("ml_top_features"),
            "explanation": alert.get("explanation"),
        }
        for col in _ALERT_NUMBERS:
            value = alert.get(col)
            record[col] = None if value is None or (isinstance(value, float) and pd.isna(value)) else float(value)
        if row is not None:
            record["features"] = {c: float(row[c]) for c in FEATURE_COLUMNS if c in row
                                  and pd.notna(row[c])}
        records.append(record)
    return records


def ingest(df: pd.DataFrame, alerts: pd.DataFrame, db: Database) -> list[int]:
    """Score-engine output -> alert rows (+ device last_seen upserts).

    Only rows the engine actually flagged (is_alert) become alert records;
    every row still updates device last_seen so the device registry reflects
    all observed traffic.
    """
    flagged = alerts[alerts["is_alert"]] if "is_alert" in alerts.columns else alerts
    ids = []
    for record in alerts_to_records(df, flagged):
        if record["device_id"]:
            db.upsert_device(record["device_id"])
        ids.append(db.insert_alert(**record))
    for record in alerts_to_records(df, alerts.drop(flagged.index, errors="ignore")):
        if record["device_id"]:
            db.upsert_device(record["device_id"])
    db.audit("ingest", "alerts_persisted", {"count": len(ids)})
    return ids
