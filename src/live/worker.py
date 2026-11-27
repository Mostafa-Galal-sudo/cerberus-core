"""E1 detection worker: reads subscriber-written rows and drives the defense agent.

The baseline is fitted once on the seeded benign window snapshot. Subsequent
alerts come from the existing HybridDetector plus two explicit live rules
(unknown device id, short burst). Every incident is created through the normal
DefenseAgent -> PolicyGate path; there is no synthetic detection fallback here.
"""
from __future__ import annotations

import argparse
import threading
import time
from datetime import datetime
from typing import Any, Callable

import pandas as pd

from src.agents.defense_agent import DefenseAgent
from src.detection.features import FEATURE_NAMES, device_windows, to_matrix
from src.detection.hybrid import HybridDetector
from src.incidents import IncidentStore
from src.policy import PolicyGate
from src.simulator.devices import PROFILES
from src.storage import db

HOST = "127.0.0.1"
PORT = 1883
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_BURST_MIN_EVENTS = 10
_BURST_MAX_SPAN_SEC = 10.0
_BURST_MIN_RATE = 5.0


def utc_log(message: str) -> None:
    print(f"[{db.utc_now()}] {message}", flush=True)


class LiveDetectionWorker:
    def __init__(
        self,
        conn: Any,
        *,
        interval: float = 2.0,
        cooldown: float = 30.0,
        detector: HybridDetector | None = None,
        defense_agent: DefenseAgent | None = None,
    ) -> None:
        self.conn = conn
        self.interval = float(interval)
        self.cooldown = float(cooldown)
        self.gate = PolicyGate(conn=conn)
        self.incidents = IncidentStore(conn)
        self.detector = detector or HybridDetector(feature_set="mqtt")
        self.defense = defense_agent or DefenseAgent(conn, self.gate, self.incidents)
        self.last_id = int(
            conn.execute("SELECT COALESCE(MAX(id), 0) FROM mqtt_events").fetchone()[0]
        )
        self._last_alert: dict[str, float] = {}
        self._fitted = False
        self._baseline_payload_max = 0.0
        self._baseline_devices: set[str] = set()
        self._known_ids = {p.device_id for p in PROFILES}

    # ------------------------------------------------------------------
    def _windows_df(self, devices: set[str] | None = None):
        windows = device_windows(self.conn)
        if devices is not None:
            windows = [w for w in windows if w.get("device_id") in devices]
        if not windows:
            return None, []
        x, meta = to_matrix(windows)
        frame = pd.DataFrame(x, columns=list(FEATURE_NAMES))
        frame["device_id"] = [m.get("device_id") for m in meta]
        frame["window_start"] = [m.get("window_start") for m in meta]
        return frame, meta

    def fit_baseline(self) -> bool:
        frame, _ = self._windows_df()
        if frame is None or len(frame) < 3:
            utc_log("[worker] baseline pending: need at least 3 benign windows")
            return False
        self.detector.fit(frame)
        self._baseline_payload_max = float(frame["payload_max"].median())
        self._baseline_devices = set(frame["device_id"].astype(str))
        self._fitted = True
        utc_log(
            f"[worker] baseline fitted windows={len(frame)} "
            f"devices={frame['device_id'].nunique()}"
        )
        return True

    # ------------------------------------------------------------------
    def _detector_detections(self, frame, meta) -> list[dict[str, Any]]:
        if not self._fitted or frame is None:
            return []
        result = self.detector.predict(frame)
        out: list[dict[str, Any]] = []
        for i, row in result.iterrows():
            if not int(row.get("alert", 0)):
                continue
            dev = str(frame.iloc[i]["device_id"])
            if dev not in self._baseline_devices:
                # No benign baseline for this device: rules below still apply,
                # but deviation evidence would be unsupported.
                continue
            out.append({
                "device_id": dev,
                "severity": str(row.get("severity", "medium")),
                "confidence": float(row.get("confidence", 0.0)),
                "explanation": str(row.get("explanation", "")),
                "detection_ref": f"live-det-{dev}-{int(time.time())}-{i}",
                "window_meta": meta[i] if i < len(meta) else {},
            })
        return out

    def _rule_detections(self, rows) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        by_device: dict[str, list[Any]] = {}
        for row in rows:
            dev = str(row["device_id"])
            if dev == "operator":
                continue
            if dev not in self._known_ids and not any(d["device_id"] == dev for d in out):
                out.append({
                    "device_id": dev,
                    "severity": "high",
                    "confidence": 0.9,
                    "explanation": f"live rule: device_id {dev!r} is not in the configured lab profiles",
                    "detection_ref": f"live-unknown-{dev}-{int(time.time())}",
                    "window_meta": {},
                })
            by_device.setdefault(dev, []).append(row)

        if self._baseline_payload_max > 0:
            ceiling = max(self._baseline_payload_max * 3.0, self._baseline_payload_max + 300.0)
            for dev, items in by_device.items():
                biggest = max(int(r["payload_size"]) for r in items)
                if biggest > ceiling and not any(d["device_id"] == dev for d in out):
                    out.append({
                        "device_id": dev,
                        "severity": "high",
                        "confidence": min(biggest / ceiling, 1.0),
                        "explanation": (
                            f"live rule: payload {biggest}B exceeds benign ceiling {ceiling:.0f}B"
                        ),
                        "detection_ref": f"live-bloat-{dev}-{int(time.time())}",
                        "window_meta": {"payload_max": biggest, "benign_ceiling": ceiling},
                    })

        for dev, items in by_device.items():
            times = []
            for item in items:
                try:
                    times.append(datetime.fromisoformat(str(item["ts_utc"]).replace("Z", "+00:00")).timestamp())
                except ValueError:
                    continue
            if len(items) < _BURST_MIN_EVENTS or len(times) < 2:
                continue
            span = max(times) - min(times)
            if span <= 0:
                span = 0.5
            rate = len(items) / span
            if len(items) >= _BURST_MIN_EVENTS and span <= _BURST_MAX_SPAN_SEC and rate >= _BURST_MIN_RATE:
                out.append({
                    "device_id": dev,
                    "severity": "high" if rate >= 10.0 else "medium",
                    "confidence": min(rate / 20.0, 1.0),
                    "explanation": (
                        f"live rule: {len(items)} events from {dev} in {span:.2f}s "
                        f"({rate:.1f}/s)"
                    ),
                    "detection_ref": f"live-burst-{dev}-{int(time.time())}",
                    "window_meta": {"events": len(items), "span_sec": span, "rate_per_sec": rate},
                })
        return out

    def poll_once(self) -> int:
        rows = self.conn.execute(
            "SELECT id, ts_utc, device_id, topic, qos, payload_size, direction "
            "FROM mqtt_events WHERE id > ? ORDER BY id",
            (self.last_id,),
        ).fetchall()
        if not rows:
            return 0
        self.last_id = int(rows[-1]["id"])

        if not self._fitted:
            self.fit_baseline()

        devices = {str(r["device_id"]) for r in rows if str(r["device_id"]) != "operator"}
        frame, meta = self._windows_df(devices)
        candidates = self._detector_detections(frame, meta) + self._rule_detections(rows)
        if not candidates:
            return 0

        candidates.sort(key=lambda d: _SEVERITY_RANK.get(str(d["severity"]), 2), reverse=True)
        now = time.monotonic()
        selected: list[dict[str, Any]] = []
        seen: set[str] = set()
        for detection in candidates:
            dev = str(detection["device_id"])
            if dev in seen:
                continue
            if now - self._last_alert.get(dev, float("-inf")) < self.cooldown:
                continue
            seen.add(dev)
            self._last_alert[dev] = now
            selected.append(detection)

        for detection in selected:
            result = self.defense.investigate(detection)
            utc_log(
                f"[worker] incident={result.incident.id} device={detection['device_id']} "
                f"severity={detection['severity']} status={result.incident.status} "
                f"isolated={bool(result.isolation and result.isolation.executed)}"
            )
        return len(selected)

    def run_forever(
        self,
        *,
        stop_event: threading.Event | None = None,
        on_tick: Callable[[], None] | None = None,
    ) -> None:
        self.fit_baseline()
        utc_log(f"[worker] ready: interval={self.interval}s cooldown={self.cooldown}s")
        try:
            while stop_event is None or not stop_event.is_set():
                try:
                    self.poll_once()
                except Exception as exc:
                    utc_log(f"[worker] poll error: {type(exc).__name__}: {exc}")
                if on_tick is not None:
                    on_tick()
                if stop_event is None:
                    time.sleep(self.interval)
                else:
                    stop_event.wait(self.interval)
        except KeyboardInterrupt:
            pass
        finally:
            utc_log("[worker] stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description="CERBERUS E1 live detection worker")
    parser.add_argument("--db", default=db.DEFAULT_DB_PATH)
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--cooldown", type=float, default=30.0)
    args = parser.parse_args()
    conn = db.open_db(args.db)
    try:
        LiveDetectionWorker(
            conn, interval=args.interval, cooldown=args.cooldown
        ).run_forever()
    finally:
        conn.close()


if __name__ == "__main__":
    main()
