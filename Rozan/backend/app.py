"""Flask backend entrypoint — REST API over the SQLite persistence layer.

Serves /health plus the /api/* routes used by the SOC dashboard and the
gateway pipeline.
"""
from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

import config
from backend.db import ALERT_STATUSES, DEVICE_STATUSES, Database

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    db = Database(db_path or config.DB_PATH).init()
    app.extensions["cerberus_db"] = db

    @app.get("/health")
    def health():
        return jsonify(status="ok", project="cerberus")

    # -- SOC dashboard (static frontend) ------------------------------------
    @app.get("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/<path:filename>")
    def frontend_assets(filename: str):
        return send_from_directory(FRONTEND_DIR, filename)

    # -- alerts -------------------------------------------------------------
    @app.post("/api/alerts")
    def post_alerts():
        body = request.get_json(silent=True)
        records = body.get("alerts") if isinstance(body, dict) else None
        if records is None and isinstance(body, dict) and body:
            records = [body]
        if not isinstance(records, list) or not records:
            return jsonify(error="expected {\"alerts\": [...]}"), 400
        ids = []
        try:
            for record in records:
                if not isinstance(record, dict) or not record:
                    return jsonify(error="each alert must be a non-empty object"), 400
                if record.get("device_id"):
                    db.upsert_device(str(record["device_id"]))
                ids.append(db.insert_alert(**record))
        except (ValueError, TypeError) as exc:
            return jsonify(error=str(exc)), 400
        db.audit("api", "alerts_ingested", {"count": len(ids)})
        return jsonify(ids=ids), 201

    @app.get("/api/alerts")
    def get_alerts():
        status = request.args.get("status")
        if status is not None and status not in ALERT_STATUSES:
            return jsonify(error=f"status must be one of {ALERT_STATUSES}"), 400
        limit = min(int(request.args.get("limit", 100)), 1000)
        return jsonify(alerts=db.list_alerts(status=status, limit=limit))

    @app.get("/api/alerts/<int:alert_id>")
    def get_alert(alert_id: int):
        alert = db.get_alert(alert_id)
        if alert is None:
            return jsonify(error="alert not found"), 404
        return jsonify(alert)

    @app.post("/api/alerts/<int:alert_id>/status")
    def set_alert_status(alert_id: int):
        body = request.get_json(silent=True) or {}
        status = body.get("status")
        if status not in ALERT_STATUSES:
            return jsonify(error=f"status must be one of {ALERT_STATUSES}"), 400
        if not db.set_alert_status(alert_id, status):
            return jsonify(error="alert not found"), 404
        db.audit("api", "alert_status_changed", {"alert_id": alert_id, "status": status})
        return jsonify(id=alert_id, status=status)

    # -- devices ------------------------------------------------------------
    @app.get("/api/devices")
    def get_devices():
        return jsonify(devices=db.list_devices())

    @app.put("/api/devices/<device_id>/status")
    def set_device_status(device_id: str):
        body = request.get_json(silent=True) or {}
        status = body.get("status")
        if status not in DEVICE_STATUSES:
            return jsonify(error=f"status must be one of {DEVICE_STATUSES}"), 400
        if not db.set_device_status(device_id, status):
            return jsonify(error="device not found"), 404
        db.audit("api", "device_status_changed", {"device_id": device_id, "status": status})
        return jsonify(device_id=device_id, status=status)

    # -- incidents ------------------------------------------------------------
    @app.post("/api/incidents")
    def post_incident():
        body = request.get_json(silent=True) or {}
        title = body.get("title")
        if not title:
            return jsonify(error="title is required"), 400
        alert_ids = body.get("alert_ids") or []
        if not isinstance(alert_ids, list):
            return jsonify(error="alert_ids must be a list"), 400
        incident_id = db.create_incident(title, alert_ids)
        db.append_event(incident_id, "created", f"Incident opened: {title}")
        db.audit("api", "incident_created", {"incident_id": incident_id})
        return jsonify(id=incident_id), 201

    @app.get("/api/incidents")
    def get_incidents():
        return jsonify(incidents=db.list_incidents())

    @app.get("/api/incidents/<int:incident_id>")
    def get_incident(incident_id: int):
        incident = db.get_incident(incident_id)
        if incident is None:
            return jsonify(error="incident not found"), 404
        return jsonify(incident)

    @app.get("/api/incidents/<int:incident_id>/timeline")
    def get_timeline(incident_id: int):
        if db.get_incident(incident_id) is None:
            return jsonify(error="incident not found"), 404
        return jsonify(events=db.get_timeline(incident_id))

    @app.post("/api/incidents/<int:incident_id>/events")
    def post_event(incident_id: int):
        body = request.get_json(silent=True) or {}
        event_type = body.get("event_type")
        message = body.get("message")
        if not event_type or not message:
            return jsonify(error="event_type and message are required"), 400
        event_id = db.append_event(incident_id, event_type, message)
        if event_id is None:
            return jsonify(error="incident not found"), 404
        return jsonify(id=event_id), 201

    # -- audit --------------------------------------------------------------
    @app.get("/api/audit")
    def get_audit():
        limit = min(int(request.args.get("limit", 100)), 1000)
        return jsonify(entries=db.list_audit(limit=limit))

    return app


if __name__ == "__main__":
    create_app().run(host=config.FLASK_HOST, port=config.FLASK_PORT)
