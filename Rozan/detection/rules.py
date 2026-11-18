"""Deterministic rule-based detection layer.

Rules are fast, explainable signatures evaluated per traffic row. Each fired
rule returns its name and a reason string — these become part of the alert's
explanation alongside SHAP/LIME output.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd


@dataclass(frozen=True)
class Rule:
    name: str
    description: str
    severity: str  # "low" | "medium" | "high"
    weight: float  # contribution to rule_score, 0..1
    check: object  # Callable[[pd.Series], bool]
    reason: object  # Callable[[pd.Series], str]

    def evaluate(self, row: pd.Series) -> tuple[str, str] | None:
        if self.check(row):
            return (self.name, self.reason(row))
        return None


def _reason(name: str, **facts: object) -> str:
    detail = ", ".join(f"{k}={v}" for k, v in facts.items())
    return f"{name}: {detail}"


def _make(name: str, description: str, severity: str, weight: float, check, fact_keys) -> Rule:
    def reason(row: pd.Series) -> str:
        facts = {k: round(float(row[k]), 2) for k in fact_keys if k in row.index}
        return _reason(name, **facts)

    return Rule(name=name, description=description, severity=severity,
                weight=weight, check=check, reason=reason)


# Ordered by severity. Thresholds are calibrated against CICIoT2023 feature
# statistics (see docs) and the simulated profiles in detection/simulator.py.
RULES: list[Rule] = [
    _make(
        "flood_rate", "Packet rate far above benign IoT baseline", "high", 1.0,
        lambda r: r.get("Rate", 0) > 10_000 and r.get("syn_flag_number", 0) > 0.5,
        ("Rate", "syn_flag_number"),
    ),
    _make(
        "syn_no_ack", "SYN-only flow at elevated rate (scan/flood)", "medium", 0.8,
        lambda r: r.get("Rate", 0) > 500 and r.get("syn_flag_number", 0) > 0.5
        and r.get("ack_flag_number", 0) < 0.1,
        ("Rate", "syn_flag_number", "ack_flag_number"),
    ),
    _make(
        "reset_storm", "Abnormal RST count (refused/flooded connections)", "medium", 0.6,
        lambda r: r.get("rst_count", 0) > 5,
        ("rst_count",),
    ),
    _make(
        "oversized_header", "Header length far above normal frame sizes", "medium", 0.6,
        lambda r: r.get("Header_Length", 0) > 500,
        ("Header_Length",),
    ),
    _make(
        "volume_spike", "Total traffic volume far above device baseline", "high", 0.9,
        lambda r: r.get("Tot_sum", 0) > 5_000,
        ("Tot_sum",),
    ),
    _make(
        "icmp_anomaly", "ICMP present with elevated rate (ICMP flood)", "medium", 0.6,
        lambda r: r.get("ICMP", 0) > 0.5 and r.get("Rate", 0) > 1_000,
        ("ICMP", "Rate"),
    ),
    _make(
        "arp_activity", "ARP traffic observed (possible ARP spoofing)", "low", 0.3,
        lambda r: r.get("ARP", 0) > 0.5,
        ("ARP",),
    ),
]


@dataclass
class RulesResult:
    """Per-row rule evaluation output aligned with the input index."""
    hits: list[list[tuple[str, str]]] = field(default_factory=list)
    score: list[float] = field(default_factory=list)

    def to_frame(self, index: pd.Index) -> pd.DataFrame:
        return pd.DataFrame(
            {"rule_hits": self.hits, "rule_score": self.score}, index=index,
        )


def run_rules(df: pd.DataFrame, rules: list[Rule] | None = None) -> RulesResult:
    """Evaluate every rule against every row of `df` (one traffic row each)."""
    result = RulesResult()
    for _, row in df.iterrows():
        fired: list[tuple[str, str]] = []
        for rule in (rules or RULES):
            if (hit := rule.evaluate(row)) is not None:
                fired.append(hit)
        result.hits.append(fired)
        result.score.append(
            min(sum(RULE_WEIGHTS[r[0]] for r in fired), 1.0) if fired else 0.0
        )
    return result


RULE_WEIGHTS: dict[str, float] = {r.name: r.weight for r in RULES}
