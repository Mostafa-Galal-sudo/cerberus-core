from __future__ import annotations

import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from src.storage.db import utc_now, write_lock


@dataclass
class IsolationRecord:
    id: int
    device_id: str
    status: str
    reason: str
    actor: str
    started_utc: str
    expires_utc: str | None = None
    released_utc: str | None = None
    incident_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IsolationRegistry:
    """SQLite-backed isolation state + expiry/step-down tracking per device."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def expire_stale(self, now_utc: str | None = None) -> int:
        now = now_utc or utc_now()
        with write_lock():
            cur = self.conn.execute(
                "UPDATE isolations SET status = 'expired', released_utc = ? "
                "WHERE status = 'active' AND expires_utc IS NOT NULL AND expires_utc <= ?",
                (now, now),
            )
            self.conn.commit()
            return cur.rowcount

    def is_isolated(self, device_id: str, now_utc: str | None = None) -> bool:
        self.expire_stale(now_utc=now_utc)
        row = self.conn.execute(
            "SELECT 1 FROM isolations WHERE device_id = ? AND status = 'active' LIMIT 1",
            (device_id,),
        ).fetchone()
        return row is not None

    def activate(
        self,
        device_id: str,
        *,
        reason: str,
        actor: str,
        ttl_sec: int | None = 300,
        incident_id: str | None = None,
    ) -> IsolationRecord:
        now_dt = datetime.now(timezone.utc)
        started = now_dt.isoformat(timespec="milliseconds")
        expires = (
            (now_dt + timedelta(seconds=ttl_sec)).isoformat(timespec="milliseconds")
            if ttl_sec is not None
            else None
        )

        with write_lock():
            # Supersede any prior active isolation on the same device cleanly
            self.conn.execute(
                "UPDATE isolations SET status = 'released', released_utc = ? "
                "WHERE device_id = ? AND status = 'active'",
                (started, device_id),
            )
            cur = self.conn.execute(
                "INSERT INTO isolations "
                "(device_id, status, reason, actor, started_utc, expires_utc, incident_id) "
                "VALUES (?, 'active', ?, ?, ?, ?, ?)",
                (device_id, reason, actor, started, expires, incident_id),
            )
            self.conn.commit()
            row_id = cur.lastrowid

        row = self.conn.execute("SELECT * FROM isolations WHERE id = ?", (row_id,)).fetchone()
        return IsolationRecord(**dict(row))

    def release(self, device_id: str, *, now_utc: str | None = None) -> int:
        now = now_utc or utc_now()
        with write_lock():
            cur = self.conn.execute(
                "UPDATE isolations SET status = 'released', released_utc = ? "
                "WHERE device_id = ? AND status = 'active'",
                (now, device_id),
            )
            self.conn.commit()
            return cur.rowcount

    def list_isolations(
        self,
        *,
        active_only: bool = False,
        device_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        self.expire_stale()
        clauses: list[str] = []
        params: list[Any] = []
        if active_only:
            clauses.append("status = 'active'")
        if device_id is not None:
            clauses.append("device_id = ?")
            params.append(device_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = self.conn.execute(
            f"SELECT * FROM isolations {where} ORDER BY id DESC LIMIT ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]
