from __future__ import annotations

import json
import socket
import socketserver
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from src.capture import (
    CaptureScopeError,
    lab_capture_filter,
    latest_capture_status,
    list_interfaces,
    resolve_interface,
    start_capture,
    write_metadata,
)
from src.capture import capture as capture_module
from src.capture import reader as reader_module
from src.dashboard import create_app


def test_lab_capture_filter_only_lab_ports():
    text = lab_capture_filter(8000)
    assert "tcp port 1883" in text
    assert "tcp port 8000" in text
    assert "udp port 1883" in text
    assert "8883" not in text
    assert "0.0.0.0/0" not in text


def test_non_loopback_interface_requires_isolated_lan_assertion(monkeypatch):
    fake = [{"index": "5", "name": "\\Device\\NPF_Ethernet", "description": "Ethernet"}]
    monkeypatch.setattr(capture_module, "list_interfaces", lambda: fake)

    with pytest.raises(CaptureScopeError, match="isolated-LAN assertion"):
        resolve_interface("Ethernet", env={})

    selected = resolve_interface(
        "Ethernet", env={"CERBERUS_CAPTURE_LAN_ISOLATED": "1"}
    )
    assert selected["is_loopback"] is False
    assert selected["scope_assertion"] == "user-asserted isolated LAN"


def test_loopback_interface_is_allowed_without_assertion(monkeypatch):
    fake = [{"index": "11", "name": "\\Device\\NPF_Loopback", "description": "Adapter for loopback traffic capture"}]
    monkeypatch.setattr(capture_module, "list_interfaces", lambda: fake)
    selected = resolve_interface("loopback", env={})
    assert selected["is_loopback"] is True
    assert selected["scope_assertion"] == "loopback (local-only)"


def test_metadata_sheet_records_scope_and_integrity(tmp_path):
    pcap = tmp_path / "cerberus_lab_20260101T000000Z.pcap"
    meta = {
        "status": "complete",
        "started_utc": "2026-01-01T00:00:00.000+00:00",
        "ended_utc": "2026-01-01T00:00:03.000+00:00",
        "interface": {"name": "\\Device\\NPF_Loopback", "scope_assertion": "loopback (local-only)"},
        "filter": "tcp port 1883 or tcp port 8000 or udp port 1883",
        "pcap": str(pcap),
        "sha256": "abc123",
        "file_bytes": 128,
        "summary": {"packets": 7, "lab_only": True},
        "db_path": "data/lab/live.db",
    }
    json_path, md_path = write_metadata(pcap, meta)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["sha256"] == "abc123"
    sheet = md_path.read_text(encoding="utf-8")
    assert "| Status | complete |" in sheet
    assert "loopback (local-only)" in sheet
    assert "`/api/capture`" in sheet
    assert "| Lab-only | True |" in sheet


def test_reader_counts_protocols_and_flags_outside_endpoints(monkeypatch, tmp_path):
    pcap = tmp_path / "sample.pcap"
    pcap.write_bytes(b"pcap")
    epoch = datetime.now(timezone.utc).timestamp()
    stdout = "\n".join([
        f"{epoch}|127.0.0.1|127.0.0.1|||MQTT",
        f"{epoch + 1}|127.0.0.1|8.8.8.8|||TCP",
    ])
    monkeypatch.setattr(
        reader_module.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=stdout, stderr=""),
    )

    summary = reader_module.summarise_pcap(pcap, tshark="tshark")
    assert summary["packets"] == 2
    assert summary["protocols"] == {"MQTT": 1, "TCP": 1}
    assert summary["outside_endpoints"] == ["8.8.8.8"]
    assert summary["lab_only"] is False
    assert summary["first_packet_utc"] and summary["last_packet_utc"]


def test_latest_capture_status_reads_the_same_pcap(monkeypatch, tmp_path):
    capture_module._METADATA_CACHE.clear()
    pcap = tmp_path / "cerberus_lab_20260101T000000Z.pcap"
    pcap.write_bytes(b"pcap")
    meta = {
        "status": "complete",
        "pcap": str(pcap),
        "lab_nets": ["127.0.0.0/8", "::1/128"],
        "summary": {"packets": 3},
    }
    (tmp_path / "cerberus_lab_20260101T000000Z.meta.json").write_text(
        json.dumps(meta), encoding="utf-8"
    )
    monkeypatch.setattr(
        reader_module, "summarise_pcap",
        lambda *a, **k: {
            "pcap": str(pcap), "packets": 9, "protocols": {"TCP": 9},
            "lab_only": True, "outside_endpoints": [],
        },
    )

    status = latest_capture_status(tmp_path)
    assert status["available"] is True
    assert status["source"] == "pcap"
    assert status["same_traffic"] is True
    assert status["summary"]["packets"] == 9  # pcap wins over cached metadata value
    capture_module._METADATA_CACHE.clear()


def test_dashboard_capture_endpoint_uses_pcap(monkeypatch, tmp_path):
    capture_module._METADATA_CACHE.clear()
    cap_dir = tmp_path / "captures"
    cap_dir.mkdir()
    pcap = cap_dir / "cerberus_lab_20260101T000000Z.pcap"
    pcap.write_bytes(b"pcap")
    meta = {
        "status": "complete",
        "pcap": str(pcap),
        "lab_nets": ["127.0.0.0/8", "::1/128"],
        "summary": {"packets": 2},
    }
    (cap_dir / "cerberus_lab_20260101T000000Z.meta.json").write_text(
        json.dumps(meta), encoding="utf-8"
    )
    monkeypatch.setenv("CERBERUS_CAPTURE_DIR", str(cap_dir))
    monkeypatch.setattr(
        reader_module, "summarise_pcap",
        lambda *a, **k: {
            "pcap": str(pcap), "packets": 11, "protocols": {"MQTT": 11},
            "lab_only": True, "outside_endpoints": [],
        },
    )

    app = create_app(db_path=tmp_path / "dash.db")
    with TestClient(app) as client:
        status = client.get("/api/capture").json()
        assert status["available"] is True
        assert status["same_traffic"] is True
        assert status["summary"]["packets"] == 11
        assert status["metadata"]["pcap"] == str(pcap)
    capture_module._METADATA_CACHE.clear()


def test_dashboard_capture_endpoint_without_metadata(monkeypatch, tmp_path):
    monkeypatch.setenv("CERBERUS_CAPTURE_DIR", str(tmp_path / "empty"))
    app = create_app(db_path=tmp_path / "dash.db")
    with TestClient(app) as client:
        payload = client.get("/api/capture").json()
    assert payload["available"] is False
    assert payload["source"] == "none"


def test_real_loopback_capture_smoke(tmp_path):
    """Real dumpcap/tshark capture of locally generated lab traffic only."""
    capture_module._METADATA_CACHE.clear()
    if not capture_module.find_binary("dumpcap") or not capture_module.find_binary("tshark"):
        pytest.skip("Wireshark dumpcap/tshark are not installed")

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.recv(64)
            except OSError:
                pass

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def generate_lab_traffic(_meta):
        for _ in range(10):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
                    conn.sendall(b"E6-LAB-PROBE")
            except OSError:
                pass
            time.sleep(0.2)

    try:
        meta = start_capture(
            seconds=4, port=port, out_dir=tmp_path, on_start=generate_lab_traffic,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    assert meta["status"] == "complete"
    assert meta["summary"]["packets"] > 0
    assert meta["summary"]["lab_only"] is True
    assert Path(meta["pcap"]).exists()
    assert Path(meta["pcap"]).with_suffix(".meta.md").exists()
    capture_module._METADATA_CACHE.clear()
