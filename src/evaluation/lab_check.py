import argparse
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from src.detection.features import device_windows
from src.detection.fingerprint import DeviceFingerprint
from src.detection.hybrid import HybridDetector
from src.storage import db

BASE = datetime(2026, 11, 26, 9, 0, tzinfo=timezone.utc)
TRAIN_END = 1800.0
NORMAL_END = 2400.0
ANOMALY_END = 2520.0

DEVICES = {
    "esp32_climate_01": {"topic": "lab/room1/climate", "interval": 10.0, "size": 180},
    "esp32_motion_01": {"topic": "lab/room2/motion", "interval": 12.0, "size": 120},
    "esp32_plug_01": {"topic": "lab/room3/power", "interval": 15.0, "size": 240},
}

ROGUE = {"device_id": "esp32_rogue_99", "topic": "lab/room9/unknown", "interval": 5.0, "size": 400}


def _write(conn, device_id, topic, start, duration, interval, size, rng, device_type="sim"):
    elapsed = 0.0
    while elapsed < duration:
        stamp = BASE + timedelta(seconds=start + elapsed)
        db.save_event(conn, {
            "ts_utc": stamp.isoformat(),
            "device_id": device_id,
            "device_type": device_type,
            "topic": topic,
            "qos": 0,
            "payload_size": int(size),
            "payload_preview": "{}",
            "direction": "publish",
        })
        elapsed += interval * rng.uniform(0.9, 1.1)


def _build_events(conn, seed=0):
    rng = np.random.default_rng(seed)
    for device_id, spec in DEVICES.items():
        _write(conn, device_id, spec["topic"], 0.0, TRAIN_END, spec["interval"], spec["size"], rng)
        _write(conn, device_id, spec["topic"], TRAIN_END, NORMAL_END - TRAIN_END, spec["interval"], spec["size"], rng)
    _write(conn, "esp32_climate_01", DEVICES["esp32_climate_01"]["topic"], NORMAL_END, ANOMALY_END - NORMAL_END, 0.2, 200, rng)
    _write(conn, "esp32_plug_01", DEVICES["esp32_plug_01"]["topic"], NORMAL_END, ANOMALY_END - NORMAL_END, 15.0, 1200, rng)
    _write(conn, ROGUE["device_id"], ROGUE["topic"], NORMAL_END, ANOMALY_END - NORMAL_END, ROGUE["interval"], ROGUE["size"], rng)


def run_lab_check(seed=0, workdir=None):
    workdir = Path(workdir or tempfile.mkdtemp(prefix="cerberus_lab_"))
    database = workdir / "lab.db"
    conn = db.open_db(database)
    _build_events(conn, seed=seed)

    rows = device_windows(conn)
    frame = pd.DataFrame(rows)
    offset = frame["window_start"] - BASE.timestamp()

    train_mask = offset < TRAIN_END
    normal_mask = (offset >= TRAIN_END) & (offset < NORMAL_END)
    anomaly_mask = offset >= NORMAL_END

    train_frame = frame[train_mask].reset_index(drop=True)
    fingerprint = DeviceFingerprint().fit(train_frame.to_dict("records"))
    detector = HybridDetector(quantile=0.995, fingerprint=fingerprint, feature_set="mqtt").fit(train_frame)

    hybrid = detector.predict(frame)
    fp_preds, fp_scores, fp_drivers = fingerprint.predict(rows)

    frame = frame.assign(
        hybrid_alert=hybrid["alert"].to_numpy(),
        rule_hits=hybrid["rule_hits"].to_numpy(),
        deviation_alert=detector.baseline.predict(frame)[0],
        fp_alert=fp_preds,
        fp_score=fp_scores,
        explanation=hybrid["explanation"].to_numpy(),
    )

    flood = frame[anomaly_mask & (frame["device_id"] == "esp32_climate_01")]
    bloat = frame[anomaly_mask & (frame["device_id"] == "esp32_plug_01")]
    rogue = frame[anomaly_mask & (frame["device_id"] == ROGUE["device_id"])]
    normal = frame[normal_mask]

    return {
        "database": str(database),
        "train_windows": int(train_mask.sum()),
        "normal_windows": int(normal_mask.sum()),
        "normal_alert_rate": float(normal["hybrid_alert"].mean()) if len(normal) else 0.0,
        "normal_fp_alert_rate": float(normal["fp_alert"].mean()) if len(normal) else 0.0,
        "flood_windows": int(len(flood)),
        "flood_rule_alerts": int(flood["rule_hits"].gt(0).sum()),
        "flood_fp_alerts": int(flood["fp_alert"].sum()),
        "flood_hybrid_alerts": int(flood["hybrid_alert"].sum()),
        "bloat_windows": int(len(bloat)),
        "bloat_rule_alerts": int(bloat["rule_hits"].gt(0).sum()),
        "bloat_fp_alerts": int(bloat["fp_alert"].sum()),
        "bloat_hybrid_alerts": int(bloat["hybrid_alert"].sum()),
        "rogue_windows": int(len(rogue)),
        "rogue_fp_alerts": int(rogue["fp_alert"].sum()),
        "rogue_hybrid_alerts": int(rogue["hybrid_alert"].sum()),
        "rogue_known": bool(fingerprint.known(ROGUE["device_id"])),
        "fingerprint_threshold": float(fingerprint.threshold_),
        "baseline_limit": float(detector.baseline.limit_),
        "examples": {
            "flood": flood.loc[flood["hybrid_alert"] == 1, "explanation"].head(1).tolist(),
            "bloat": bloat.loc[bloat["hybrid_alert"] == 1, "explanation"].head(1).tolist(),
            "normal_false_positive": normal.loc[normal["hybrid_alert"] == 1, "explanation"].head(1).tolist(),
        },
    }


def evaluate_db(db_path, split_ts, min_events=4):
    conn = db.open_db(db_path)
    try:
        rows = device_windows(conn, min_events=min_events)
    finally:
        conn.close()

    frame = pd.DataFrame(rows)
    split_epoch = datetime.fromisoformat(split_ts).timestamp()
    train_frame = frame[frame["window_start"] < split_epoch].reset_index(drop=True)
    test_frame = frame[frame["window_start"] >= split_epoch].reset_index(drop=True)

    fingerprint = DeviceFingerprint().fit(train_frame.to_dict("records"))
    detector = HybridDetector(quantile=0.995, fingerprint=fingerprint, feature_set="mqtt").fit(train_frame)
    hybrid = detector.predict(test_frame)
    fp_preds, fp_scores, _ = fingerprint.predict(test_frame.to_dict("records"))

    scored = test_frame.assign(
        hybrid_alert=hybrid["alert"].to_numpy(),
        rule_hits=hybrid["rule_hits"].to_numpy(),
        fp_alert=fp_preds,
        fp_score=fp_scores,
        explanation=hybrid["explanation"].to_numpy(),
    )

    per_device = {}
    for device_id, group in scored.groupby("device_id"):
        per_device[device_id] = {
            "windows": int(len(group)),
            "rule_alerts": int(group["rule_hits"].gt(0).sum()),
            "fp_alerts": int(group["fp_alert"].sum()),
            "hybrid_alerts": int(group["hybrid_alert"].sum()),
            "known": bool(fingerprint.known(device_id)),
            "sample_explanation": group.loc[group["hybrid_alert"] == 1, "explanation"].head(1).tolist(),
        }

    return {
        "database": str(db_path),
        "train_windows": int(len(train_frame)),
        "test_windows": int(len(test_frame)),
        "fingerprint_threshold": float(fingerprint.threshold_),
        "baseline_limit": float(detector.baseline.limit_),
        "per_device": per_device,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CERBERUS C2-T09 lab detection check")
    parser.add_argument("--db", default=None, help="Existing SQLite DB path (e.g. data/lab/lab_traffic.db)")
    parser.add_argument("--split-ts", default=None, help="UTC ISO8601 timestamp splitting train vs anomaly windows")
    args = parser.parse_args()

    if args.db and args.split_ts:
        import json
        print(json.dumps(evaluate_db(args.db, args.split_ts), indent=2))
    else:
        report = run_lab_check()
        for key, value in report.items():
            if key == "examples":
                continue
            print(f"{key:24s} {value}")
        for name, samples in report["examples"].items():
            print(f"\n{name}: {samples[0] if samples else 'no alert'}")
