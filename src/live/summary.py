"""Small evidence helper: print a one-line summary of a live-run DB."""
from __future__ import annotations

import argparse
import json
import sqlite3
from typing import Any

from src.storage import db


def summarize(db_path: str) -> dict[str, Any]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        total = conn.execute("SELECT COUNT(*) FROM mqtt_events").fetchone()[0]
        incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        open_incidents = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'investigating')"
        ).fetchone()[0]
        active_isolations = conn.execute(
            "SELECT COUNT(*) FROM isolations WHERE status = 'active'"
        ).fetchone()[0]
        denies = conn.execute(
            "SELECT COUNT(*) FROM policy_audit WHERE verdict = 'DENY'"
        ).fetchone()[0]
        attack_ids: set[str] = set()
        for row in conn.execute(
            "SELECT context_json FROM policy_audit WHERE action LIKE 'attack_%'"
        ).fetchall():
            try:
                context = json.loads(row["context_json"] or "{}")
            except (ValueError, TypeError):
                continue
            if context.get("attack_id"):
                attack_ids.add(str(context["attack_id"]))
        return {
            "events": total,
            "incidents": incidents,
            "open_incidents": open_incidents,
            "active_isolations": active_isolations,
            "denies": denies,
            "attacks": len(attack_ids),
        }
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="CERBERUS live-run DB summary")
    parser.add_argument("--db", default=db.DEFAULT_DB_PATH)
    args = parser.parse_args()
    stats = summarize(str(args.db))
    print(
        "events={events} incidents={incidents} open_incidents={open_incidents} "
        "active_isolations={active_isolations} denies={denies} attacks={attacks}".format(**stats)
    )


if __name__ == "__main__":
    main()
