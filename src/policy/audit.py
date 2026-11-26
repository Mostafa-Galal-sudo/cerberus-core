from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from src.storage.db import utc_now, write_lock


class AuditLogger:
    """Append-only audit logger writing to SQLite policy_audit and optional JSONL."""

    def __init__(
        self,
        conn: sqlite3.Connection | None = None,
        log_path: str | Path | None = None,
    ) -> None:
        self.conn = conn
        self.log_path = Path(log_path) if log_path is not None else None
        if self.log_path is not None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        verdict: str,
        reason: str,
        context: dict[str, Any] | None = None,
        ts_utc: str | None = None,
    ) -> dict[str, Any]:
        ts = ts_utc or utc_now()
        ctx_json = json.dumps(context or {}, sort_keys=True)
        entry = {
            "ts_utc": ts,
            "actor": actor,
            "action": action,
            "target": target,
            "verdict": verdict,
            "reason": reason,
            "context": context or {},
        }

        if self.conn is not None:
            with write_lock():
                self.conn.execute(
                    "INSERT INTO policy_audit "
                    "(ts_utc, actor, action, target, verdict, reason, context_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (ts, actor, action, target, verdict, reason, ctx_json),
                )
                self.conn.commit()

        if self.log_path is not None:
            with write_lock():
                with self.log_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, sort_keys=True) + "\n")

        return entry

    def query(
        self,
        *,
        limit: int = 100,
        actor: str | None = None,
        verdict: str | None = None,
    ) -> list[dict[str, Any]]:
        if self.conn is None:
            return []
        clauses: list[str] = []
        params: list[Any] = []
        if actor is not None:
            clauses.append("actor = ?")
            params.append(actor)
        if verdict is not None:
            clauses.append("verdict = ?")
            params.append(verdict)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self.conn.execute(
            f"SELECT id, ts_utc, actor, action, target, verdict, reason, context_json "
            f"FROM policy_audit {where} ORDER BY id DESC LIMIT ?",
            params,
        ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            raw_ctx = item.pop("context_json", None)
            item["context"] = json.loads(raw_ctx) if raw_ctx else {}
            results.append(item)
        return results
