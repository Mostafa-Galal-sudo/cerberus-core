"""Canonical CICIoT2023 feature schema and label taxonomy.

The official dataset ships 46 numeric features + a `label` column. Raw CSV
column spellings vary slightly between releases (e.g. "Protocol Type" vs
"Protocol_type"); everything is normalized to the canonical names here.
"""
from __future__ import annotations

# 46 numeric features, in dataset order.
FEATURE_COLUMNS: list[str] = [
    "flow_duration",
    "Header_Length",
    "Protocol_Type",
    "Time_To_Live",
    "Duration",
    "Rate",
    "Srate",
    "Drate",
    "fin_flag_number",
    "syn_flag_number",
    "rst_flag_number",
    "psh_flag_number",
    "ack_flag_number",
    "ece_flag_number",
    "cwr_flag_number",
    "urg_flag_number",
    "ack_count",
    "syn_count",
    "fin_count",
    "urg_count",
    "rst_count",
    "HTTP",
    "HTTPS",
    "DNS",
    "Telnet",
    "SMTP",
    "SSH",
    "IRC",
    "TCP",
    "UDP",
    "DHCP",
    "ARP",
    "ICMP",
    "IPv",
    "LLC",
    "Tot_sum",
    "Min",
    "Max",
    "AVG",
    "Std",
    "Tot_size",
    "IAT",
    "Number",
    "Magnitue",
    "Radius",
    "Covariance",
    "Variance",
    "Weight",
]

LABEL_COLUMN = "label"
BINARY_COLUMN = "is_attack"  # 0 = benign, 1 = attack
CATEGORY_COLUMN = "attack_class"  # one of ATTACK_CLASSES

ATTACK_CLASSES = ["DDoS", "DoS", "Mirai", "Recon", "Web-based", "BruteForce", "Spoofing"]

# Ordered rules: first match wins. Raw labels use forms like
# "DDoS-SYN_Flood", "DoS-TCP_Flood", "Mirai-greip_flood", "Recon-PingSweep",
# "VulnerabilityScan", "DictionaryBruteForce", "MITM-ArpSpoofing", "XSS".
# "DDoS" must be checked before "DoS" because "DDoS" contains "DoS".
_LABEL_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("DDoS", ("ddos",)),
    ("DoS", ("dos-", "dos_", "dos ")),
    ("Mirai", ("mirai",)),
    ("Recon", ("recon", "vulnerabilityscan", "vulnerability scan", "portscan",
               "port scan", "pingsweep", "ping sweep", "osscan", "os scan",
               "hostdiscovery", "host discovery")),
    ("Web-based", ("xss", "sqlinjection", "sql injection", "commandinjection",
                   "command injection", "backdoor", "uploading", "browserhijacking",
                   "browser hijacking")),
    ("BruteForce", ("bruteforce", "brute force", "dictionary")),
    ("Spoofing", ("spoofing", "arp", "dns_spoof", "dns spoof", "mitm")),
]

BENIGN_LABEL = "BenignTraffic"


def normalize_column(name: str) -> str:
    """Normalize a raw CICIoT2023 column name to the canonical schema.

    Case- and separator-insensitive matching against FEATURE_COLUMNS, plus a
    few dataset-typo aliases ("Magnitude" -> "Magnitue").
    """
    cleaned = name.strip().lower().replace("-", "_").replace(" ", "_")
    canonical = {c.lower(): c for c in FEATURE_COLUMNS}
    aliases = {
        "magnitude": "Magnitue",  # dataset's own typo — keep canonical
        "label": LABEL_COLUMN,
    }
    if cleaned in aliases:
        return aliases[cleaned]
    if cleaned == "label":
        return LABEL_COLUMN
    if cleaned in canonical:
        return canonical[cleaned]
    return cleaned


def label_to_category(label: str) -> str:
    """Map a raw CICIoT2023 label string to its attack class or Benign."""
    text = label.strip().lower()
    if not text or text.startswith("benign"):
        return BENIGN_LABEL
    for category, needles in _LABEL_RULES:
        if any(needle in text for needle in needles):
            return category
    raise ValueError(f"Unknown CICIoT2023 label: {label!r}")


def binary_target(category: str) -> int:
    """0 = benign, 1 = attack."""
    return 0 if category == BENIGN_LABEL else 1
