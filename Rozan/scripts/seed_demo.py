"""Seed a demo database and launch the SOC dashboard locally.

Usage:
    .venv\\Scripts\\python.exe scripts\\seed_demo.py [--db demo.db] [--port 5000]

Generates simulated traffic, runs the hybrid detection engine, annotates
alerts with SHAP, persists everything, and opens an incident — so the
dashboard at http://127.0.0.1:<port>/ has data to show. Local-only.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app import create_app
from backend.ingest import ingest
from detection.engine import HybridDetector
from detection.explain import Explainer, annotate_alerts
from detection.simulator import generate_traffic


def seed(db_path: str) -> None:
    app = create_app(db_path)
    db = app.extensions["cerberus_db"]

    benign = generate_traffic({"mqtt_benign": 400}, seed=101)
    engine = HybridDetector().fit(benign)

    df = generate_traffic(
        {"mqtt_benign": 30, "mqtt_flood": 15, "wifi_deauth": 8, "mqtt_spoof": 5},
        seed=102,
    )
    devices = ["cam-1", "thermo-2", "plug-3", "speaker-4"]
    df["device_id"] = [devices[i % len(devices)] for i in range(len(df))]

    alerts = engine.score(df)
    annotated = annotate_alerts(df, alerts, Explainer(engine.forest, benign))
    ids = ingest(df, annotated, db)
    print(f"seeded {len(ids)} alerts ({sum(1 for i in ids)})")

    alert_ids = [i for i in ids if db.get_alert(i)["is_attack"]]
    incident_id = db.create_incident("MQTT flood against camera subnet", alert_ids[:5])
    db.append_event(incident_id, "detection", "Flood signature confirmed by hybrid engine")
    db.append_event(incident_id, "investigation", "Defense agent correlating RF + MQTT telemetry")
    db.append_event(incident_id, "response", "cam-1 isolated by policy-bounded response")
    db.set_device_status("cam-1", "isolated")
    print(f"incident #{incident_id} created with {min(5, len(alert_ids))} alerts")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="demo.db")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    seed(args.db)
    app = create_app(args.db)
    print(f"SOC dashboard: http://127.0.0.1:{args.port}/")
    app.run(host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
