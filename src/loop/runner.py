"""
Cerberus Closed-Loop Runner  (C3-T08)
======================================
Wires the full pipeline in-process (no broker required):

  AttackAgent.run_scenario()
      → events written to SQLite
      → HybridDetector / RuleEngine detection
      → DefenseAgent.investigate(detection)
      → PolicyGate → isolate_device()
      → optional SSE push callback

Usage
-----
    from src.loop.runner import CerberusLoop
    from src.storage.db import open_db

    conn = open_db("data/lab/lab_traffic.db")
    loop = CerberusLoop(conn)
    result = loop.run_once()          # one attack + defend cycle
    loop.run(cycles=3, interval=0.5)  # repeated cycles
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import sqlite3

from src.agents.attack_agent import AttackAgent, AttackExecutionResult
from src.agents.defense_agent import DefenseAgent, DefenseResult
from src.detection.features import device_windows, to_matrix
from src.detection.hybrid import HybridDetector
from src.incidents import IncidentStore
from src.policy import PolicyGate
from src.storage.db import open_db

logger = logging.getLogger(__name__)


@dataclass
class LoopResult:
    cycle: int
    attack: AttackExecutionResult
    detections: list[dict[str, Any]]
    defense: DefenseResult | None
    duration_sec: float
    error: str | None = None


@dataclass
class CerberusLoop:
    """Single-threaded closed-loop orchestrator — no MQTT broker required."""

    conn: sqlite3.Connection
    gate: PolicyGate = field(default=None)           # type: ignore[assignment]
    incidents: IncidentStore = field(default=None)   # type: ignore[assignment]
    detector: HybridDetector = field(default=None)   # type: ignore[assignment]
    attack_agent: AttackAgent = field(default=None)  # type: ignore[assignment]
    defense_agent: DefenseAgent = field(default=None) # type: ignore[assignment]
    on_event: Callable[[dict[str, Any]], None] | None = None  # SSE / UI callback

    def __post_init__(self) -> None:
        if self.gate is None:
            self.gate = PolicyGate(conn=self.conn)
        if self.incidents is None:
            self.incidents = IncidentStore(self.conn)
        if self.detector is None:
            # lightweight detector: rules-only (no training data needed for demo)
            self.detector = HybridDetector(feature_set="mqtt")
        if self.attack_agent is None:
            self.attack_agent = AttackAgent(
                self.conn, self.gate, mqtt_client=None  # no broker → events go straight to DB
            )
        if self.defense_agent is None:
            self.defense_agent = DefenseAgent(
                self.conn, self.gate, self.incidents
            )

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _detect(self, target_device: str) -> list[dict[str, Any]]:
        """Run detection on recent windows for *target_device*.

        Returns a list of detection dicts (one per alert row), possibly empty.
        """
        all_windows = device_windows(self.conn)
        # Filter to only windows for the target device
        windows = [w for w in all_windows if w.get("device_id") == target_device]
        if not windows:
            return []

        try:
            x, meta = to_matrix(windows)
        except Exception as exc:
            logger.warning("feature extraction failed: %s", exc)
            return []

        import pandas as pd
        import numpy as np

        df = pd.DataFrame(x, columns=None)  # numeric only
        # Attach feature-name columns if possible
        from src.detection.features import FEATURE_NAMES
        if x.shape[1] == len(FEATURE_NAMES):
            df = pd.DataFrame(x, columns=list(FEATURE_NAMES))
        if "device_id" not in df.columns:
            df["device_id"] = [m.get("device_id", target_device) for m in meta]

        # Fit detector on the same data if not yet fitted (demo / no training set)
        try:
            result_df = self.detector.predict(df)
        except Exception:
            # Baseline not fitted — fit on benign-like rows then re-predict
            self.detector.fit(df)
            result_df = self.detector.predict(df)

        alerts = []
        for i, row in result_df.iterrows():
            if int(row.get("alert", 0)):
                alerts.append({
                    "device_id": target_device,
                    "severity": str(row.get("severity", "medium")),
                    "confidence": float(row.get("confidence", 0.0)),
                    "explanation": str(row.get("explanation", "")),
                    "detection_ref": f"loop-det-{target_device}-{i}",
                    "window_meta": meta[i] if i < len(meta) else {},
                })
        return alerts

    # ------------------------------------------------------------------
    # Single cycle
    # ------------------------------------------------------------------

    def run_once(
        self,
        attack_prompt: str = "Generate a lab MQTT flood attack scenario.",
        attack_count: int = 20,
        attack_target: str | None = None,
    ) -> LoopResult:
        """Execute one full attack → detect → defend cycle."""
        t0 = time.monotonic()
        cycle_n = getattr(self, "_cycle_count", 0) + 1
        self._cycle_count = cycle_n  # type: ignore[attr-defined]

        # --- 1. Attack ---
        try:
            atk = self.attack_agent.run_scenario(
                attack_prompt,
                count=attack_count,
                interval=0.0,
            )
        except Exception as exc:
            logger.error("attack_agent.run_scenario failed: %s", exc)
            return LoopResult(
                cycle=cycle_n,
                attack=None,  # type: ignore[arg-type]
                detections=[],
                defense=None,
                duration_sec=time.monotonic() - t0,
                error=str(exc),
            )

        target = attack_target or (atk.plan or {}).get("target", "esp32_temp_01")
        if self.on_event:
            self.on_event({"type": "attack", "cycle": cycle_n, "result": str(atk)})

        # --- 2. Detect ---
        detections = self._detect(str(target))
        if not detections:
            # Even if the ML layer is quiet, create a synthetic detection from the
            # attack result so the defense agent always gets something to work with.
            detections = [{
                "device_id": str(target),
                "severity": "high" if atk.executed else "medium",
                "confidence": 0.75 if atk.executed else 0.4,
                "explanation": f"attack_agent:{atk.mode}:events={atk.events_injected}",
                "detection_ref": f"loop-synthetic-{cycle_n}",
                "window_meta": {},
            }]

        if self.on_event:
            self.on_event({"type": "detections", "cycle": cycle_n, "count": len(detections)})

        # --- 3. Defend (investigate + possibly isolate) ---
        # Use the highest-severity detection as the trigger.
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        top_det = max(detections, key=lambda d: sev_order.get(d.get("severity", "medium"), 2))

        defense: DefenseResult | None = None
        try:
            defense = self.defense_agent.investigate(top_det)
        except Exception as exc:
            logger.error("defense_agent.investigate failed: %s", exc)

        if self.on_event and defense is not None:
            self.on_event({
                "type": "defense",
                "cycle": cycle_n,
                "incident_id": defense.incident.id,
                "status": defense.incident.status,
                "isolated": defense.isolation is not None and defense.isolation.executed,
            })

        return LoopResult(
            cycle=cycle_n,
            attack=atk,
            detections=detections,
            defense=defense,
            duration_sec=time.monotonic() - t0,
        )

    # ------------------------------------------------------------------
    # Repeated cycles
    # ------------------------------------------------------------------

    def run(
        self,
        cycles: int = 3,
        interval: float = 1.0,
        attack_count: int = 20,
    ) -> list[LoopResult]:
        """Run *cycles* attack→detect→defend iterations, sleeping *interval* seconds between them."""
        results: list[LoopResult] = []
        for _ in range(cycles):
            result = self.run_once(attack_count=attack_count)
            results.append(result)
            logger.info(
                "cycle=%d attack=%s detections=%d incident=%s status=%s",
                result.cycle,
                result.attack.mode if result.attack else "err",
                len(result.detections),
                result.defense.incident.id if result.defense else "none",
                result.defense.incident.status if result.defense else "none",
            )
            if interval > 0 and _ < cycles - 1:
                time.sleep(interval)
        return results


def make_loop(db_path: str | None = None, **kwargs: Any) -> CerberusLoop:
    """Convenience factory: open DB, create a default CerberusLoop."""
    from src.storage.db import get_db_path
    conn = open_db(get_db_path(db_path))
    return CerberusLoop(conn=conn, **kwargs)
