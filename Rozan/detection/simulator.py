"""Simulated MQTT / 802.11 traffic generator (Phase 1, no hardware required).

Produces traffic rows in the same CICIoT2023 feature schema so the hybrid
detection engine trains and scores identically on simulated and real data.
Scenario labels are prefixed with "Sim-" and are NOT CICIoT2023 labels; they
carry their own attack-class mapping in SIM_SCENARIOS.

All simulation stays within the local lab testbed — nothing here touches an
external network (AGENTS.md safety rules).
"""
from __future__ import annotations

import random

import pandas as pd

from detection.schema import (
    BINARY_COLUMN,
    CATEGORY_COLUMN,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
)

# scenario -> (label, attack_class, is_attack)
SIM_SCENARIOS: dict[str, tuple[str, str, int]] = {
    "mqtt_benign": ("Sim-MQTT_Benign", "BenignTraffic", 0),
    "mqtt_flood": ("Sim-MQTT_Flood", "DoS", 1),
    "mqtt_injection": ("Sim-MQTT_Injection", "Spoofing", 1),
    "mqtt_spoof": ("Sim-MQTT_DeviceSpoof", "Spoofing", 1),
    "wifi_deauth": ("Sim-WiFi_Deauth", "DoS", 1),
    "wifi_rogue_ap": ("Sim-WiFi_RogueAP", "Spoofing", 1),
}


def _base_benign(rng: random.Random) -> dict[str, float]:
    """Baseline resembling benign IoT MQTT telemetry in the CICIoT2023 schema."""
    return {
        "flow_duration": abs(rng.gauss(0.1, 0.05)),
        "Header_Length": rng.uniform(54, 90),
        "Protocol_Type": 6.0,  # TCP
        "Time_To_Live": rng.choice([64, 128]),
        "Duration": 64.0,
        "Rate": abs(rng.gauss(15.7, 8.0)),
        "Srate": abs(rng.gauss(15.7, 8.0)),
        "Drate": abs(rng.gauss(10.0, 5.0)),
        "fin_flag_number": rng.random() < 0.1,
        "syn_flag_number": rng.random() < 0.3,
        "rst_flag_number": rng.random() < 0.05,
        "psh_flag_number": rng.random() < 0.4,
        "ack_flag_number": rng.random() < 0.5,
        "ece_flag_number": 0.0,
        "cwr_flag_number": 0.0,
        "urg_flag_number": 0.0,
        "ack_count": max(0, rng.gauss(0.5, 0.2)),
        "syn_count": max(0, rng.gauss(0.5, 0.2)),
        "fin_count": max(0, rng.gauss(0.1, 0.1)),
        "urg_count": 0.0,
        "rst_count": max(0, rng.gauss(0.1, 0.05)),
        "HTTP": 0.0, "HTTPS": 0.0, "DNS": 0.0, "Telnet": 0.0,
        "SMTP": 0.0, "SSH": 0.0, "IRC": 0.0,
        "TCP": 1.0, "UDP": 0.0, "DHCP": 0.0, "ARP": 0.0, "ICMP": 0.0,
        "IPv": 1.0, "LLC": 1.0,
        "Tot_sum": rng.uniform(500, 600), "Min": 54.0, "Max": 55.0,
        "AVG": 54.0, "Std": rng.uniform(0.0, 0.4), "Tot_size": rng.uniform(500, 600),
        "IAT": 83_100_000.0, "Number": 9.5, "Magnitue": 10.3,
        "Radius": abs(rng.gauss(0.2, 0.1)), "Covariance": 0.0,
        "Variance": rng.uniform(0.0, 0.08), "Weight": 141.5,
    }


def _attack_profile(row: dict[str, float], scenario: str, rng: random.Random) -> dict[str, float]:
    """Apply scenario-specific deviations on top of the benign baseline."""
    if scenario in ("mqtt_flood", "wifi_deauth"):
        # Flood signature: very high packet rate, SYN/RST-heavy, tiny flows.
        row.update({
            "Rate": 100_000.0 + rng.uniform(0, 50_000),
            "Srate": 100_000.0 + rng.uniform(0, 50_000),
            "Drate": 0.0,
            "syn_flag_number": 1.0,
            "rst_flag_number": float(rng.random() < 0.8),
            "syn_count": rng.uniform(8, 12),
            "rst_count": rng.uniform(0, 8),
            "Header_Length": rng.uniform(40, 54),
        })
    elif scenario in ("mqtt_injection", "mqtt_spoof", "wifi_rogue_ap"):
        # Spoof/injection signature: normal-looking rate but anomalous size stats.
        row.update({
            "Header_Length": rng.uniform(90, 400),
            "Tot_sum": rng.uniform(700, 2_000),
            "Tot_size": rng.uniform(700, 2_000),
            "Max": rng.uniform(60, 500),
            "Std": rng.uniform(0.5, 3.0),
            "psh_flag_number": 1.0,
        })
    return row


def generate_traffic(
    scenarios: dict[str, int],
    seed: int = 42,
) -> pd.DataFrame:
    """Generate simulated traffic rows.

    `scenarios` maps a scenario key from SIM_SCENARIOS to the number of rows.
    Returns a DataFrame with the canonical CICIoT2023 schema plus
    `label`, `attack_class`, and `is_attack` columns.
    """
    if unknown := set(scenarios) - set(SIM_SCENARIOS):
        raise ValueError(f"Unknown scenarios: {sorted(unknown)}. Valid: {sorted(SIM_SCENARIOS)}")
    rng = random.Random(seed)
    rows: list[dict] = []
    for scenario, count in scenarios.items():
        label, category, is_attack = SIM_SCENARIOS[scenario]
        for _ in range(count):
            row = _base_benign(rng)
            if is_attack:
                row = _attack_profile(row, scenario, rng)
            row = {c: float(v) for c, v in row.items()}
            row[LABEL_COLUMN] = label
            row[CATEGORY_COLUMN] = category
            row[BINARY_COLUMN] = is_attack
            rows.append(row)
    df = pd.DataFrame(rows, columns=[*FEATURE_COLUMNS, LABEL_COLUMN, CATEGORY_COLUMN, BINARY_COLUMN])
    return df.astype({c: "float64" for c in FEATURE_COLUMNS})
