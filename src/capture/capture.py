"""E6 — bounded, lab-only packet capture with a UTC-named pcap and metadata sheet.

The capture is passive. By default it binds to a loopback interface and filters only
the lab MQTT port and the dashboard port. A non-loopback interface is refused unless
the operator explicitly asserts that the interface is an isolated lab segment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LAB_NETS = ("127.0.0.0/8", "::1/128")
_METADATA_CACHE: dict[str, dict[str, Any]] = {}


class CaptureError(RuntimeError):
    """Capture tooling or capture output is unavailable/invalid."""


class CaptureScopeError(CaptureError):
    """The requested interface or captured endpoints are outside the lab scope."""


def default_capture_dir() -> Path:
    configured = os.environ.get("CERBERUS_CAPTURE_DIR")
    return Path(configured) if configured else ROOT / "data" / "lab" / "captures"


def find_binary(name: str) -> str | None:
    """Locate a Wireshark binary even when it is not on PATH (common on Windows)."""
    found = shutil.which(name)
    if found:
        return found
    candidates = [os.environ.get("CERBERUS_CAPTURE_BIN_DIR", "")]
    candidates.extend(
        [
            r"C:\Program Files\Wireshark",
            r"C:\Program Files (x86)\Wireshark",
        ]
    )
    for directory in candidates:
        if not directory:
            continue
        for suffix in (".exe", ""):
            candidate = Path(directory) / f"{name}{suffix}"
            if candidate.is_file():
                return str(candidate)
    return None


def list_interfaces() -> list[dict[str, Any]]:
    binary = find_binary("dumpcap")
    if not binary:
        raise CaptureError("dumpcap not found; set CERBERUS_CAPTURE_BIN_DIR or install Wireshark")
    try:
        proc = subprocess.run(
            [binary, "-D"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureError(f"dumpcap -D failed: {exc}") from exc
    if proc.returncode != 0:
        raise CaptureError(f"dumpcap -D exited {proc.returncode}: {proc.stderr[-500:]}")

    interfaces: list[dict[str, Any]] = []
    pattern = re.compile(r"^(\d+)\.\s+(\S+)\s+\((.*)\)\s*$")
    for line in (proc.stdout or "").splitlines():
        match = pattern.match(line.strip())
        if match:
            interfaces.append(
                {"index": match.group(1), "name": match.group(2), "description": match.group(3)}
            )
    return interfaces


def resolve_interface(
    requested: str | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = env if env is not None else os.environ
    interfaces = list_interfaces()
    want = str(requested or env.get("CERBERUS_CAPTURE_INTERFACE") or "loopback").strip()
    if not interfaces:
        raise CaptureError("dumpcap reported no capture interfaces")

    match = next(
        (
            item for item in interfaces
            if want == item["index"]
            or want.lower() == item["name"].lower()
            or want.lower() in item["description"].lower()
        ),
        None,
    )
    if match is None:
        raise CaptureError(f"capture interface {want!r} not found; run dumpcap -D")

    label = f"{match['name']} {match['description']}".lower()
    is_loopback = "loopback" in label
    assertion = "loopback (local-only)"
    if not is_loopback:
        if env.get("CERBERUS_CAPTURE_LAN_ISOLATED") != "1":
            raise CaptureScopeError(
                "non-loopback capture requires explicit isolated-LAN assertion: "
                "set CERBERUS_CAPTURE_LAN_ISOLATED=1 only for an isolated lab interface"
            )
        assertion = "user-asserted isolated LAN"
    return {**match, "is_loopback": is_loopback, "scope_assertion": assertion}


def lab_capture_filter(port: int) -> str:
    parts = ["tcp port 1883"]
    if int(port) != 1883:
        parts.append(f"tcp port {int(port)}")
    parts.append("udp port 1883")
    return " or ".join(parts)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_metadata(pcap_path: Path, meta: dict[str, Any]) -> tuple[Path, Path]:
    json_path = pcap_path.with_suffix(".meta.json")
    md_path = pcap_path.with_suffix(".meta.md")
    json_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    summary = meta.get("summary") or {}
    lines = [
        "# E6 capture metadata",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Status | {meta.get('status', 'unknown')} |",
        f"| Started (UTC) | {meta.get('started_utc', '-')} |",
        f"| Ended (UTC) | {meta.get('ended_utc', '-')} |",
        f"| Interface | {meta.get('interface', {}).get('name', '-')} |",
        f"| Scope assertion | {meta.get('interface', {}).get('scope_assertion', '-')} |",
        f"| Capture filter | `{meta.get('filter', '-')}` |",
        f"| pcap | `{meta.get('pcap', '-')}` |",
        f"| Bytes | {meta.get('file_bytes', 0)} |",
        f"| SHA-256 | `{meta.get('sha256', '-')}` |",
        f"| Packets | {summary.get('packets', 0)} |",
        f"| Lab-only | {summary.get('lab_only', '-')} |",
        f"| Dashboard DB | `{meta.get('db_path', '-')}` |",
        "",
        "The dashboard reads this same pcap via `/api/capture`; no synthetic capture is used.",
        "",
    ]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def start_capture(
    *,
    seconds: int,
    port: int = 8000,
    out_dir: Path | None = None,
    db_path: str | None = None,
    interface: str | None = None,
    env: dict[str, str] | None = None,
    on_start: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    env = env if env is not None else os.environ
    if seconds <= 0:
        raise CaptureError("capture duration must be positive")
    dumpcap = find_binary("dumpcap")
    tshark = find_binary("tshark")
    if not dumpcap or not tshark:
        raise CaptureError("dumpcap and tshark are both required for E6")
    selected = resolve_interface(interface, env=env)
    net_list = tuple(
        value.strip()
        for value in str(env.get("CERBERUS_CAPTURE_LAB_NETS", ",".join(DEFAULT_LAB_NETS))).split(",")
        if value.strip()
    )
    capture_filter = lab_capture_filter(port)
    target_dir = Path(out_dir) if out_dir else default_capture_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    pcap_path = target_dir / f"cerberus_lab_{stamp}.pcap"

    meta: dict[str, Any] = {
        "status": "capturing",
        "started_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "ended_utc": None,
        "interface": selected,
        "filter": capture_filter,
        "dashboard_port": int(port),
        "db_path": str(db_path) if db_path else None,
        "pcap": str(pcap_path),
        "lab_nets": list(net_list),
        "dumpcap": dumpcap,
        "tshark": tshark,
        "file_bytes": 0,
        "sha256": None,
        "summary": None,
    }
    write_metadata(pcap_path, meta)

    command = [
        dumpcap, "-i", selected["name"], "-f", capture_filter,
        "-w", str(pcap_path), "-F", "pcap", "-a", f"duration:{seconds}", "-q",
    ]
    meta["command"] = command
    write_metadata(pcap_path, meta)
    try:
        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace",
        )
    except OSError as exc:
        meta.update(status="failed", ended_utc=datetime.now(timezone.utc).isoformat(timespec="milliseconds"), error=str(exc))
        write_metadata(pcap_path, meta)
        raise CaptureError(f"dumpcap failed: {exc}") from exc

    # The callback runs only after dumpcap is live, so generated lab traffic is
    # genuinely inside the capture window (used by the real loopback smoke test).
    if on_start is not None:
        try:
            on_start(meta)
        except Exception as exc:
            proc.kill()
            proc.communicate()
            meta.update(status="failed", ended_utc=datetime.now(timezone.utc).isoformat(timespec="milliseconds"), error=f"capture on_start failed: {exc}")
            write_metadata(pcap_path, meta)
            raise CaptureError(meta["error"]) from exc
    try:
        stdout, stderr = proc.communicate(timeout=seconds + 120)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        stdout, stderr = proc.communicate()
        meta.update(status="failed", ended_utc=datetime.now(timezone.utc).isoformat(timespec="milliseconds"), error=str(exc))
        write_metadata(pcap_path, meta)
        raise CaptureError(f"dumpcap failed: {exc}") from exc

    meta["dumpcap_log"] = ((stdout or "") + "\n" + (stderr or ""))[-2000:]
    meta["ended_utc"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    if proc.returncode != 0 or not pcap_path.exists():
        meta["status"] = "failed"
        meta["error"] = f"dumpcap exited {proc.returncode}"
        write_metadata(pcap_path, meta)
        raise CaptureError(meta["error"])

    from .reader import summarise_pcap

    summary = summarise_pcap(pcap_path, lab_nets=net_list, tshark=tshark)
    meta.update(
        status="complete",
        file_bytes=pcap_path.stat().st_size,
        sha256=_sha256(pcap_path),
        summary=summary,
    )
    write_metadata(pcap_path, meta)
    if summary["packets"] == 0:
        raise CaptureError(f"capture contains no lab packets: {pcap_path}")
    if not summary["lab_only"]:
        raise CaptureScopeError(
            f"captured endpoints outside the lab allowlist: {summary['outside_endpoints']}"
        )
    return meta


def latest_capture_status(out_dir: Path | None = None) -> dict[str, Any]:
    """Read the newest metadata sheet and the pcap it points at (dashboard source)."""
    directory = Path(out_dir) if out_dir else default_capture_dir()
    sheets = sorted(directory.glob("*.meta.json"), key=lambda p: p.stat().st_mtime_ns, reverse=True)
    if not sheets:
        return {"available": False, "reason": "no capture metadata", "source": "none"}
    sheet = sheets[0]
    try:
        meta = json.loads(sheet.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"available": False, "reason": f"unreadable metadata: {exc}", "source": "metadata"}
    pcap_path = Path(str(meta.get("pcap", "")))
    summary = meta.get("summary")
    cache_key = f"{sheet.stat().st_mtime_ns}:{pcap_path}"
    cached = _METADATA_CACHE.get(cache_key)
    if cached is not None:
        summary = cached
        source = "pcap-cache"
    elif pcap_path.exists() and meta.get("status") == "complete":
        try:
            from .reader import summarise_pcap

            summary = summarise_pcap(
                pcap_path,
                lab_nets=tuple(meta.get("lab_nets") or DEFAULT_LAB_NETS),
            )
            if len(_METADATA_CACHE) > 8:
                _METADATA_CACHE.clear()
            _METADATA_CACHE[cache_key] = summary
            source = "pcap"
        except CaptureError:
            source = "metadata"
    else:
        source = "metadata"
    return {
        "available": True,
        "source": source,
        "metadata_sheet": str(sheet),
        "metadata": meta,
        "summary": summary,
        "same_traffic": source in ("pcap", "pcap-cache") and summary is not None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="E6 bounded lab capture")
    parser.add_argument("--seconds", type=int, required=True)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", default=None)
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--interface", default=None)
    args = parser.parse_args(argv)
    try:
        def announce(started: dict[str, Any]) -> None:
            print(f"[capture] started {started['pcap']}", flush=True)
            print(f"[capture] metadata {Path(started['pcap']).with_suffix('.meta.json')}", flush=True)

        meta = start_capture(
            seconds=args.seconds, port=args.port,
            out_dir=Path(args.out_dir) if args.out_dir else None,
            db_path=args.db, interface=args.interface, on_start=announce,
        )
    except CaptureError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}))
        return 2
    print(json.dumps({
        "status": "complete",
        "pcap": meta["pcap"],
        "metadata": str(Path(meta["pcap"]).with_suffix(".meta.json")),
        "packets": meta["summary"]["packets"],
        "lab_only": meta["summary"]["lab_only"],
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
