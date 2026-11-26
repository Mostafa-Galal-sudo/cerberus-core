from __future__ import annotations

from pathlib import Path
from typing import Any

from src.incidents import IncidentStore
from src.policy import AuditLogger


def extract_pcap_excerpt(
    pcap_path: str | Path | None,
    *,
    device_ip: str | None = None,
    max_packets: int = 20,
    audit: AuditLogger | None = None,
    incidents: IncidentStore | None = None,
    incident_id: str | None = None,
) -> dict[str, Any]:
    """Read-only PCAP excerpt helper. Gracefully returns unavailable in lab-sim mode."""
    target = device_ip or (str(pcap_path) if pcap_path else "none")
    path = Path(pcap_path) if pcap_path else None

    if path is None or not path.exists():
        result: dict[str, Any] = {
            "available": False,
            "pcap_path": str(path) if path else None,
            "device_ip": device_ip,
            "packet_count": 0,
            "packets": [],
            "note": "No PCAP capture file present (lab simulator mode)",
        }
    else:
        try:
            from scapy.all import rdpcap  # type: ignore[import-not-found]

            pkts = rdpcap(str(path), count=max_packets * 5)
            summaries: list[str] = []
            for pkt in pkts:
                line = pkt.summary()
                if device_ip is None or device_ip in line:
                    summaries.append(line)
                if len(summaries) >= max_packets:
                    break
            result = {
                "available": True,
                "pcap_path": str(path),
                "device_ip": device_ip,
                "packet_count": len(summaries),
                "packets": summaries,
            }
        except ImportError:
            result = {
                "available": False,
                "pcap_path": str(path),
                "device_ip": device_ip,
                "packet_count": 0,
                "packets": [],
                "note": "scapy not installed; PCAP parsing skipped",
            }

    if audit is not None:
        audit.record(
            actor="defense_tool",
            action="extract_pcap_excerpt",
            target=target,
            verdict="ALLOW",
            reason="read-only PCAP excerpt",
            context={"available": result["available"], "packet_count": result["packet_count"]},
        )
    if incidents is not None and incident_id is not None:
        incidents.append_event(
            incident_id,
            kind="tool_call",
            actor="defense_tool",
            summary=f"PCAP excerpt check ({result['packet_count']} packets)",
            details=result,
        )
    return result
