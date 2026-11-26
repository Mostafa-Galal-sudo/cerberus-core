from __future__ import annotations

from src.agents.tools import (
    device_deviation_report,
    extract_pcap_excerpt,
    query_device_events,
    query_incident_history,
)
from src.detection.features import device_windows
from src.detection.fingerprint import DeviceFingerprint
from src.incidents import IncidentStore
from src.policy import AuditLogger
from src.storage.db import open_db, save_event


def _seed_events(conn, device_id: str = "esp32_temp_01") -> None:
    for minute in range(4):
        for sec in ("00", "20"):
            save_event(
                conn,
                {
                    "ts_utc": f"2026-11-26T10:0{minute}:{sec}.000+00:00",
                    "device_id": device_id,
                    "device_type": "climate",
                    "topic": "lab/room1/climate",
                    "qos": 0,
                    "payload_size": 180,
                    "payload_preview": '{"temp": 22.5}',
                    "direction": "publish",
                },
            )


def test_db_tools_and_audit_and_incident_trail(tmp_path):
    conn = open_db(tmp_path / "tools.db")
    try:
        _seed_events(conn)
        audit = AuditLogger(conn=conn)
        incidents = IncidentStore(conn)
        inc = incidents.create_incident("esp32_temp_01", "medium", "det-100")

        res = query_device_events(
            conn,
            "esp32_temp_01",
            limit=4,
            audit=audit,
            incidents=incidents,
            incident_id=inc.id,
        )
        assert res["count"] == 4

        hist = query_incident_history(conn, device_id="esp32_temp_01", audit=audit)
        assert hist["count"] == 1

        audit_rows = audit.query()
        assert len(audit_rows) == 2
        timeline = incidents.get_timeline(inc.id)
        assert [e.kind for e in timeline] == ["detection", "tool_call"]
    finally:
        conn.close()


def test_fingerprint_tool_and_pcap_graceful_fallback(tmp_path):
    conn = open_db(tmp_path / "fp_tools.db")
    try:
        _seed_events(conn)
        rows = device_windows(conn, window_sec=60)
        fp = DeviceFingerprint(min_windows=2).fit(rows)

        rep = device_deviation_report(conn, "esp32_temp_01", fingerprint=fp)
        assert rep["known_device"] is True
        assert rep["windows_analyzed"] == len(rows)

        pcap = extract_pcap_excerpt(None, device_ip="192.168.1.101")
        assert pcap["available"] is False
        assert pcap["packet_count"] == 0
    finally:
        conn.close()
