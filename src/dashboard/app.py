from __future__ import annotations

import asyncio
import hmac
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

from src.agents import build_health_status
from src.incidents import IncidentStore
from src.policy import AuditLogger, PolicyGate
from src.response import IsolationRegistry, release_device
from src.simulator.devices import PROFILES
from src.storage.db import get_db_path, open_db, total_events

_STATIC_DIR = Path(__file__).parent / "static"


def require_operator(
    x_cerberus_token: str | None = Header(default=None, alias="X-Cerberus-Token"),
) -> str:
    configured = os.environ.get("CERBERUS_DASHBOARD_TOKEN")
    if not configured:
        raise HTTPException(status_code=503, detail="DASHBOARD_AUTH_NOT_CONFIGURED")
    if not x_cerberus_token or not hmac.compare_digest(x_cerberus_token, configured):
        raise HTTPException(status_code=401, detail="UNAUTHORIZED")
    return "operator"


_SERIES_MINUTES = 15
_MAX_RELEASE_REASON = 200


def _recent_minute_buckets(
    conn,
    table: str,
    *,
    minutes: int = _SERIES_MINUTES,
    verdict: str | None = None,
) -> list[dict[str, Any]]:
    """Per-minute counts for the last `minutes` whole minutes (UTC, zero-filled).

    Buckets are real wall-clock minutes, so an idle minute shows as 0 instead of
    being skipped; the chart can never imply activity that did not happen.
    """
    if table not in {"mqtt_events", "policy_audit"}:
        raise ValueError(f"unsupported series table: {table}")
    where, params = "", []
    if verdict is not None:
        if table != "policy_audit":
            raise ValueError("verdict filter is only supported for policy_audit")
        where, params = "WHERE verdict = ? AND ", [verdict]
    else:
        where = "WHERE "
    end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start = end - timedelta(minutes=minutes - 1)
    rows = conn.execute(
        "SELECT strftime('%Y-%m-%dT%H:%M', ts_utc) AS minute, COUNT(*) AS n "
        f"FROM {table} {where}ts_utc >= ? GROUP BY minute",
        (*params, start.strftime("%Y-%m-%dT%H:%M")),
    ).fetchall()
    counts = {row["minute"]: row["n"] for row in rows}
    buckets: list[dict[str, Any]] = []
    for i in range(minutes):
        key = (start + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M")
        buckets.append({"minute": key, "label": key[11:16], "count": counts.get(key, 0)})
    return buckets


def _clean_release_reason(raw: str | None) -> str:
    """Normalize an operator-supplied release reason before it reaches the audit trail."""
    text = "".join(ch if ch.isprintable() else " " for ch in (raw or ""))
    text = " ".join(text.split())[:_MAX_RELEASE_REASON].strip()
    return text or "dashboard manual release"


def _build_snapshot(conn, gate: PolicyGate) -> dict[str, Any]:
    incidents_store = IncidentStore(conn)
    reg = IsolationRegistry(conn)

    all_incidents = incidents_store.list_incidents(limit=200)
    active_isos = reg.list_isolations(active_only=True, limit=100)
    isolated_ids = {row["device_id"] for row in active_isos}

    ev_rows = conn.execute(
        "SELECT device_id, COUNT(*) AS event_count, MAX(ts_utc) AS last_seen "
        "FROM mqtt_events GROUP BY device_id"
    ).fetchall()
    ev_map = {r["device_id"]: dict(r) for r in ev_rows}

    open_by_dev: dict[str, int] = {}
    for inc in all_incidents:
        if inc["status"] in ("open", "investigating"):
            open_by_dev[inc["device_id"]] = open_by_dev.get(inc["device_id"], 0) + 1

    devices: list[dict[str, Any]] = []
    known_ids = set()
    for p in PROFILES:
        known_ids.add(p.device_id)
        stats = ev_map.get(p.device_id, {})
        if p.device_id in isolated_ids:
            dev_status = "isolated"
        elif open_by_dev.get(p.device_id, 0) > 0:
            dev_status = "alerting"
        else:
            dev_status = "healthy"
        devices.append(
            {
                "device_id": p.device_id,
                "device_type": p.device_type,
                "room": p.room,
                "hardware": p.hardware,
                "ip": p.ip,
                "mac": p.mac,
                "qos": p.qos,
                "topic": p.topics_publish[0] if p.topics_publish else p.status_topic,
                "status": dev_status,
                "event_count": stats.get("event_count", 0),
                "last_seen": stats.get("last_seen"),
                "open_incidents": open_by_dev.get(p.device_id, 0),
            }
        )

    # Include any rogue/unregistered devices seen in DB or incidents
    extra_ids = (set(ev_map) | set(open_by_dev) | isolated_ids) - known_ids
    for dev_id in sorted(extra_ids):
        stats = ev_map.get(dev_id, {})
        devices.append(
            {
                "device_id": dev_id,
                "device_type": "unknown",
                "room": "unassigned",
                "hardware": "-",
                "ip": "-",
                "mac": "-",
                "qos": "-",
                "topic": "-",
                "status": "isolated" if dev_id in isolated_ids else "alerting",
                "event_count": stats.get("event_count", 0),
                "last_seen": stats.get("last_seen"),
                "open_incidents": open_by_dev.get(dev_id, 0),
            }
        )

    denies = len(gate.audit.query(limit=500, verdict="DENY"))
    kpis = {
        "total_events": total_events(conn),
        "open_incidents": sum(1 for i in all_incidents if i["status"] in ("open", "investigating")),
        "mitigated_incidents": sum(1 for i in all_incidents if i["status"] == "mitigated"),
        "resolved_incidents": sum(1 for i in all_incidents if i["status"] == "resolved"),
        "active_isolations": len(active_isos),
        "policy_denies": denies,
        "devices_total": len(devices),
        "devices_isolated": len(isolated_ids),
    }
    series = {
        "events": _recent_minute_buckets(conn, "mqtt_events"),
        "denies": _recent_minute_buckets(conn, "policy_audit", verdict="DENY"),
    }
    return {"kpis": kpis, "devices": devices, "series": series}


def create_app(db_path: str | Path | None = None) -> FastAPI:
    load_dotenv()
    resolved_db = get_db_path(db_path)
    conn = open_db(resolved_db)
    gate = PolicyGate(conn=conn)
    incidents_store = IncidentStore(conn)
    registry = IsolationRegistry(conn)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        conn.close()

    app = FastAPI(title="Cerberus-Core SOC Dashboard", version="0.3.0", lifespan=lifespan)
    app.state.db_path = resolved_db
    app.state.conn = conn
    app.state.gate = gate

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        html_file = _STATIC_DIR / "index.html"
        return HTMLResponse(html_file.read_text(encoding="utf-8"))

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        snap = _build_snapshot(conn, gate)
        providers = build_health_status()
        return {
            "status": "ok",
            "db_path": str(resolved_db),
            # Legacy fields kept for existing dashboards; no key value is exposed.
            "llm_mode": {
                "groq": "live" if os.environ.get("GROQ_API_KEY") else "fallback",
                "deepseek": "live" if os.environ.get("DEEPSEEK_API_KEY") else "fallback",
            },
            "providers": providers,
            **snap["kpis"],
        }

    @app.get("/api/overview")
    def overview() -> dict[str, Any]:
        return _build_snapshot(conn, gate)

    @app.get("/api/incidents")
    def list_incidents(
        status: str | None = None,
        severity: str | None = None,
        device_id: str | None = None,
        q: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, Any]:
        items = incidents_store.list_incidents(status=status, device_id=device_id, limit=limit)
        if severity:
            items = [i for i in items if i["severity"] == severity]
        if q:
            needle = q.lower()
            items = [
                i
                for i in items
                if needle in i["device_id"].lower()
                or needle in (i.get("reasoning_summary") or "").lower()
                or needle in i["detection_ref"].lower()
                or needle in i["id"].lower()
            ]
        return {"count": len(items), "incidents": items}

    @app.get("/api/incidents/{incident_id}")
    def get_incident(incident_id: str) -> dict[str, Any]:
        inc = incidents_store.get_incident(incident_id)
        if inc is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return inc

    @app.get("/api/isolations")
    def list_isolations(
        active_only: bool = False,
        device_id: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, Any]:
        items = registry.list_isolations(active_only=active_only, device_id=device_id, limit=limit)
        return {"count": len(items), "isolations": items}

    @app.post("/api/isolations/{device_id}/release")
    def release_isolated_device(
        device_id: str,
        incident_id: str | None = None,
        reason: str | None = None,
        actor: str = Depends(require_operator),
    ) -> dict[str, Any]:
        release_reason = _clean_release_reason(reason)
        res = release_device(
            conn,
            gate,
            device_id,
            actor=actor,
            reason=release_reason,
            incident_id=incident_id,
            incidents=incidents_store if incident_id else None,
            context={"source": "dashboard", "authenticated": True, "reason": release_reason},
        )
        if not res.decision.allowed:
            raise HTTPException(status_code=403, detail=res.decision.reason)
        return {
            "released": res.executed,
            "device_id": device_id,
            "reason": release_reason,
            "policy_reason": res.decision.reason,
        }

    @app.get("/api/audit")
    def list_audit(
        actor: str | None = None,
        verdict: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, Any]:
        items = gate.audit.query(limit=limit, actor=actor, verdict=verdict)
        return {"count": len(items), "audit": items}

    def build_stream_payload() -> dict[str, Any]:
        # Sync SQLite work must not run on the ASGI event loop: a busy database
        # would otherwise stall unrelated requests such as /api/health.
        return {
            **_build_snapshot(conn, gate),
            "incidents": incidents_store.list_incidents(limit=25),
            "isolations": registry.list_isolations(limit=25),
            "audit": gate.audit.query(limit=100),
        }

    @app.get("/api/stream")
    async def stream(once: bool = False) -> StreamingResponse:
        async def event_gen():
            while True:
                payload = await run_in_threadpool(build_stream_payload)
                yield f"data: {json.dumps(payload)}\n\n"
                if once:
                    break
                await asyncio.sleep(2.0)

        return StreamingResponse(event_gen(), media_type="text/event-stream")

    return app
