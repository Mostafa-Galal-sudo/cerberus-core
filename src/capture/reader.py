"""Read a captured pcap back into dashboard-facing statistics."""

from __future__ import annotations

import ipaddress
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .capture import CaptureError, find_binary

_FIELDS = (
    "frame.time_epoch",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "_ws.col.Protocol",
)


def _networks(lab_nets: tuple[str, ...] | list[str]) -> list[ipaddress._BaseNetwork]:
    return [ipaddress.ip_network(str(value), strict=False) for value in lab_nets]


def _inside(address: str, nets: list[ipaddress._BaseNetwork]) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return True  # non-IP frames are not endpoint claims
    return any(parsed in net for net in nets)


def _iso(epoch: str) -> str | None:
    try:
        return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat(timespec="milliseconds")
    except (TypeError, ValueError):
        return None


def summarise_pcap(
    path: Path | str,
    *,
    lab_nets: tuple[str, ...] | list[str] | None = None,
    tshark: str | None = None,
) -> dict[str, Any]:
    """Return packet counts, protocol mix, and a lab-only endpoint check."""
    pcap = Path(path)
    if not pcap.exists():
        raise CaptureError(f"pcap not found: {pcap}")
    binary = tshark or find_binary("tshark")
    if not binary:
        raise CaptureError("tshark not found; cannot read the captured pcap")
    nets = _networks(tuple(lab_nets) if lab_nets else ("127.0.0.0/8", "::1/128"))
    command = [binary, "-r", str(pcap), "-T", "fields", "-E", "separator=|"]
    for field in _FIELDS:
        command.extend(["-e", field])
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureError(f"tshark read failed: {exc}") from exc
    if proc.returncode != 0:
        raise CaptureError(f"tshark exited {proc.returncode}: {proc.stderr[-500:]}")

    packets = 0
    first: str | None = None
    last: str | None = None
    protocols: Counter[str] = Counter()
    outside: list[str] = []
    for raw in (proc.stdout or "").splitlines():
        if not raw.strip():
            continue
        fields = (raw.split("|") + [""] * len(_FIELDS))[: len(_FIELDS)]
        packets += 1
        stamp = _iso(fields[0])
        if stamp:
            first = first or stamp
            last = stamp
        protocol = fields[5].strip() or "UNKNOWN"
        protocols[protocol] += 1
        for address in fields[1:5]:
            address = address.strip()
            if address and not _inside(address, nets) and address not in outside:
                outside.append(address)

    return {
        "pcap": str(pcap),
        "packets": packets,
        "first_packet_utc": first,
        "last_packet_utc": last,
        "protocols": dict(protocols.most_common(12)),
        "lab_nets": [str(net) for net in nets],
        "outside_endpoints": outside[:20],
        "lab_only": not outside,
    }
