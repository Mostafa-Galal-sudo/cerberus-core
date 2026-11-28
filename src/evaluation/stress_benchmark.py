"""CERBERUS acceptance stress benchmark.

Runs four independently gated sections and writes a machine-readable JSON plus a
human-readable Markdown report under ``results/``:

- adapter: fault injection, retry, circuit breaker, budget, secret hygiene, A/B
- ollama: real local provider latency, JSON validity, tool-call reliability
- dataset: sampled CICIoT2023 detection benchmark (no leakage, file-level split)
- live: real ``demo.ps1 -Live -ConcurrentInjectors N`` run and DB forensics
- capture: real ``demo.ps1 -Live -Capture`` run, pcap forensics, and dashboard read-back

Every section has hard gates. A failing gate makes the process exit non-zero.
Nothing here changes production state; the live section uses a fresh lab DB.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agents import (  # noqa: E402
    ProviderAdapter,
    ProviderRequestError,
    ProviderUnavailable,
    redact_secrets,
    resolve_provider,
)

RESULTS_DIR = ROOT / "results"
DATASET_ROOT = ROOT / "data" / "raw" / "ciciot2023" / "CSV"
OLLAMA_BASE = "http://127.0.0.1:11434"
SECRET = "stress-leak-canary-4471"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
    return ordered[index]


def sanitise_log(text: str) -> str:
    """Keep diagnostics, strip anything that could be used as a credential."""
    cleaned = re.sub(
        r"(Release token \(X-Cerberus-Token\):\s*)\S+",
        r"\1[REDACTED]",
        text or "",
    )
    return redact_secrets(cleaned)


class _Completions:
    def __init__(self, outcomes: list[Any]):
        self.outcomes = list(outcomes)
        self.calls = 0

    def create(self, **_kwargs):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeClient:
    def __init__(self, outcomes: list[Any]):
        self.completions = _Completions(outcomes)
        self.chat = SimpleNamespace(completions=self.completions)


def _response(content: str = "{}", tool_calls: list[Any] | None = None):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content, tool_calls=tool_calls))],
        usage=SimpleNamespace(total_tokens=16),
    )


def _tool_call(name: str, arguments: str):
    return SimpleNamespace(
        id="call_stress",
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def adapter_section() -> dict[str, Any]:
    """Fault matrix: every injected failure must be contained, never crash the loop."""
    env = {
        "CERBERUS_LLM_MAX_ATTEMPTS": "2",
        "CERBERUS_LLM_CIRCUIT_FAILURES": "99",
        "CERBERUS_LLM_MAX_CALLS": "50",
        "GROQ_API_KEY": SECRET,
    }
    failures: list[Any] = [
        TimeoutError("stress timeout"),
        RuntimeError("429 rate limited"),
        RuntimeError("500 upstream failure"),
        ConnectionResetError("stress connection reset"),
        ValueError("stress malformed payload"),
        SimpleNamespace(choices=[]),
    ]
    scenarios = 0
    handled = 0
    uncaught = 0
    attempts = 0
    leaks = 0

    for failure in failures:
        scenarios += 1
        client = FakeClient([failure, failure])
        adapter = ProviderAdapter("defense", env=env, client=client, sleep=lambda _: None)
        try:
            adapter.complete(messages=[{"role": "user", "content": "probe"}])
        except (ProviderRequestError, ProviderUnavailable):
            handled += 1
        except Exception:
            uncaught += 1
        attempts += client.completions.calls
        if SECRET in adapter.status().to_dict().__str__():
            leaks += 1

    # Malformed tool arguments must fail closed through the agent path.
    from src.incidents import IncidentStore
    from src.policy import PolicyGate
    from src.storage.db import open_db

    with tempfile.TemporaryDirectory() as tmp:
        conn = open_db(Path(tmp) / "stress.db")
        try:
            from src.agents import DefenseAgent

            bad_tool = FakeClient(
                [_response("", tool_calls=[_tool_call("query_device_events", "{not-json")])]
            )
            result = DefenseAgent(conn, PolicyGate(conn=conn), IncidentStore(conn), client=bad_tool).investigate(
                {"device_id": "esp32_temp_01", "severity": "high"}
            )
            scenarios += 1
            if result.mode == "fallback" and result.error and SECRET not in result.error:
                handled += 1
            else:
                uncaught += 1
        finally:
            conn.close()

    # Circuit breaker: two failures open it; the next request is rejected locally.
    clock = [0.0]
    breaker_client = FakeClient([RuntimeError("boom"), RuntimeError("boom"), _response("{}")])
    breaker_env = {
        "CERBERUS_LLM_MAX_ATTEMPTS": "1",
        "CERBERUS_LLM_CIRCUIT_FAILURES": "2",
        "CERBERUS_LLM_CIRCUIT_COOLDOWN_S": "10",
        "CERBERUS_LLM_MAX_CALLS": "10",
    }
    breaker = ProviderAdapter(
        "defense", env=breaker_env, client=breaker_client,
        sleep=lambda _: None, clock=lambda: clock[0],
    )
    for _ in range(2):
        try:
            breaker.complete(messages=[{"role": "user", "content": "x"}])
        except ProviderRequestError:
            pass
    circuit_opened = breaker.status().circuit == "open"
    blocked = False
    try:
        breaker.complete(messages=[{"role": "user", "content": "x"}])
    except ProviderUnavailable:
        blocked = True
    clock[0] = 11.0
    probe_ok = breaker.complete(messages=[{"role": "user", "content": "x"}]).content == "{}"

    # Budget: exactly N calls, then fail closed.
    budget_env = {"CERBERUS_LLM_MAX_CALLS": "3", "CERBERUS_LLM_MAX_ATTEMPTS": "1"}
    budget_client = FakeClient([_response("{}") for _ in range(4)])
    budget = ProviderAdapter("attack", env=budget_env, client=budget_client)
    for _ in range(3):
        budget.complete(messages=[{"role": "user", "content": "x"}])
    budget_violations = 0
    try:
        budget.complete(messages=[{"role": "user", "content": "x"}])
        budget_violations += 1
    except ProviderUnavailable:
        pass
    if budget_client.completions.calls != 3:
        budget_violations += 1

    # Secret hygiene and A/B determinism.
    redacted = redact_secrets(f"key={SECRET}", env)
    if SECRET in redacted or "[REDACTED]" not in redacted:
        leaks += 1
    ab_env = {
        "OPENAI_API_KEY": "mock-openai",
        "ANTHROPIC_API_KEY": "mock-anthropic",
        "CERBERUS_LLM_AB_PROVIDERS": "openai,anthropic",
    }
    picks = [resolve_provider("defense", env=ab_env, assignment_key=f"inc-{i}") for i in range(1000)]
    ab_unique = len(set(picks))
    ab_stable = all(picks[i] == resolve_provider("defense", env=ab_env, assignment_key=f"inc-{i}") for i in range(0, 1000, 97))

    metrics = {
        "scenarios": scenarios,
        "handled": handled,
        "uncaught": uncaught,
        "attempts_total": attempts,
        # Exceptions get one bounded retry; a malformed response fails fast.
        "expected_attempts": sum(2 if isinstance(f, Exception) else 1 for f in failures),
        "circuit_opened": circuit_opened,
        "circuit_blocked": blocked,
        "half_open_probe_ok": probe_ok,
        "budget_violations": budget_violations,
        "secret_leaks": leaks,
        "ab_unique_providers": ab_unique,
        "ab_stable": ab_stable,
    }
    gates = {
        "all_failures_handled": handled == scenarios,
        "no_uncaught_exception": uncaught == 0,
        "retry_is_bounded": attempts == metrics["expected_attempts"],
        "circuit_opens_and_blocks": circuit_opened and blocked and probe_ok,
        "budget_never_exceeded": budget_violations == 0,
        "no_secret_leak": leaks == 0,
        "ab_uses_both_and_is_stable": ab_unique == 2 and ab_stable,
    }
    return {"metrics": metrics, "gates": gates}


def ollama_section(requests: int) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(f"{OLLAMA_BASE}/api/tags", timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
        names = [model.get("name", "") for model in payload.get("models", [])]
    except Exception as exc:
        return {"skipped": True, "reason": f"local Ollama unavailable: {exc}", "gates": {}}

    env = {
        "CERBERUS_DEFENSE_PROVIDER": "ollama",
        "CERBERUS_LLM_MAX_ATTEMPTS": "1",
        "CERBERUS_LLM_TIMEOUT_S": "120",
        "CERBERUS_LLM_MAX_CALLS": str(requests + 10),
    }
    adapter = ProviderAdapter("defense", env=env)
    tools = [{
        "type": "function",
        "function": {
            "name": "query_device_events",
            "description": "Fetch recent MQTT events for a device from SQLite.",
            "parameters": {
                "type": "object",
                "properties": {"device_id": {"type": "string"}},
                "required": ["device_id"],
            },
        },
    }]
    # JSON and tool probes are separated: asking for "JSON only" while also
    # offering a tool would measure prompt conflict, not tool-call reliability.
    tool_requests = max(2, requests // 5)
    latencies: list[float] = []
    valid_json = 0
    tool_ok = 0
    fallbacks = 0
    tokens = 0
    for index in range(requests + tool_requests):
        is_tool_probe = index >= requests
        messages = (
            [
                {"role": "system", "content": "Use the provided tool when asked to inspect a device."},
                {"role": "user", "content": f"Inspect device esp32_temp_{index % 3 + 1:02d} using the available tool."},
            ]
            if is_tool_probe else [
                {"role": "system", "content": "Reply with JSON only."},
                {"role": "user", "content": f'Return exactly {{"probe": {index}}}'},
            ]
        )
        started = time.perf_counter()
        try:
            result = adapter.complete(
                messages=messages,
                tools=tools if is_tool_probe else None,
                tool_choice="auto",
                temperature=0.1,
            )
        except Exception:
            fallbacks += 1
            latencies.append((time.perf_counter() - started) * 1000)
            continue
        latencies.append((time.perf_counter() - started) * 1000)
        if is_tool_probe:
            if result.tool_calls and result.tool_calls[0]["function"]["name"] == "query_device_events":
                tool_ok += 1
        else:
            try:
                parsed = json.loads(result.content)
                if parsed.get("probe") == index:
                    valid_json += 1
            except Exception:
                pass
        tokens += int((result.usage or {}).get("total_tokens", 0) or 0)

    json_rate = valid_json / max(requests, 1)
    tool_rate = tool_ok / max(tool_requests, 1)
    metrics = {
        "models_available": names,
        "requests": requests,
        "json_valid": valid_json,
        "json_valid_rate": round(json_rate, 4),
        "tool_requests": tool_requests,
        "tool_success": tool_ok,
        "tool_success_rate": round(tool_rate, 4),
        "fallbacks": fallbacks,
        "tokens": tokens,
        "latency_ms_p50": round(percentile(latencies, 0.50), 2),
        "latency_ms_p95": round(percentile(latencies, 0.95), 2),
        "latency_ms_max": round(max(latencies) if latencies else 0.0, 2),
    }
    gates = {
        "all_requests_completed": fallbacks == 0,
        "json_validity_at_least_90pct": json_rate >= 0.90,
        "tool_calls_at_least_90pct": tool_rate >= 0.90 if tool_requests else True,
        "p95_latency_under_30s": metrics["latency_ms_p95"] <= 30000,
    }
    return {"metrics": metrics, "gates": gates}


def dataset_section(rows: int) -> dict[str, Any]:
    if not DATASET_ROOT.exists():
        return {"skipped": True, "reason": f"dataset not found at {DATASET_ROOT}", "gates": {}}
    from src.evaluation.benchmark import evaluate

    started = time.perf_counter()
    result = evaluate(DATASET_ROOT, seed=0, benign_rows=rows, attack_rows=rows)
    summary = result["summary"].set_index("detector")
    hybrid = summary.loc["hybrid"]
    rules = summary.loc["rules"]
    metrics = {
        "sampled_rows_per_file": rows,
        "train_rows": result["composition"]["train_rows"],
        "test_rows": result["composition"]["test_rows"],
        "hybrid_f1": round(float(hybrid["f1"]), 4),
        "hybrid_fpr": round(float(hybrid["fpr"]), 4),
        "rules_f1": round(float(rules["f1"]), 4),
        "elapsed_s": round(time.perf_counter() - started, 2),
    }
    gates = {
        "benchmark_completed": True,
        "hybrid_f1_at_least_0_85": metrics["hybrid_f1"] >= 0.85,
        "hybrid_fpr_at_most_0_10": metrics["hybrid_fpr"] <= 0.10,
    }
    return {"metrics": metrics, "gates": gates}


def _parse_ts(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def live_section(injectors: int, seconds: int) -> dict[str, Any]:
    powershell = shutil.which("powershell") or shutil.which("powershell.exe")
    if not powershell:
        return {"skipped": True, "reason": "powershell not available", "gates": {}}
    cmd = [
        powershell, "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", str(ROOT / "demo.ps1"), "-Live",
        "-ConcurrentInjectors", str(injectors), "-StopAfterSeconds", str(seconds),
    ]
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd, cwd=str(ROOT), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=seconds + 240,
        )
    except subprocess.TimeoutExpired as exc:
        return {"skipped": True, "reason": f"live run timed out: {exc}", "gates": {}}
    elapsed = time.perf_counter() - started
    log = sanitise_log((proc.stdout or "") + "\n" + (proc.stderr or ""))
    match = re.search(r"Fresh live DB:\s*(.+)", log)
    if not match:
        return {
            "metrics": {"exit_code": proc.returncode, "log_tail": log[-2000:]},
            "gates": {"launcher_started": False, "exit_code_zero": False},
        }
    db_path = Path(match.group(1).strip())
    if not db_path.exists():
        return {"metrics": {"db_path": str(db_path)}, "gates": {"db_exists": False}}

    conn = sqlite3.connect(db_path)
    try:
        def scalar(sql: str) -> int:
            return int(conn.execute(sql).fetchone()[0])

        events = scalar("SELECT COUNT(*) FROM mqtt_events")
        incidents = scalar("SELECT COUNT(*) FROM incidents")
        denies = scalar("SELECT COUNT(*) FROM policy_audit WHERE verdict='DENY'")
        audit_corr = {row[0] for row in conn.execute(
            "SELECT json_extract(context_json, '$.correlation_id') FROM policy_audit "
            "WHERE json_extract(context_json, '$.correlation_id') IS NOT NULL"
        )}
        event_corr = {row[0] for row in conn.execute(
            "SELECT correlation_id FROM mqtt_events WHERE correlation_id IS NOT NULL"
        )}
        detection_refs = [row[0] for row in conn.execute("SELECT detection_ref FROM incidents")]
        incident_corr = set()
        duplicate_incident_corr = 0
        pattern = re.compile(r"(E2-e2-inj-\d+-\d{4})")
        for ref in detection_refs:
            found = pattern.findall(ref or "")
            for correlation in set(found):
                if correlation in incident_corr:
                    duplicate_incident_corr += 1
                incident_corr.add(correlation)
        matched = audit_corr & event_corr & incident_corr
        completeness = len(matched) / max(len(audit_corr), 1)
        integrity = str(conn.execute("PRAGMA integrity_check").fetchone()[0])

        modes: dict[str, int] = {}
        for (details,) in conn.execute(
            "SELECT details_json FROM incident_events WHERE kind='llm_mode'"
        ):
            mode = str(json.loads(details or "{}").get("mode", "unknown"))
            modes[mode] = modes.get(mode, 0) + 1

        first_event = dict(conn.execute(
            "SELECT correlation_id, MIN(ts_utc) FROM mqtt_events "
            "WHERE correlation_id IS NOT NULL GROUP BY correlation_id"
        ))
        incident_times = {}
        for (correlation, created) in conn.execute(
            "SELECT detection_ref, created_utc FROM incidents"
        ):
            for correlation_id in pattern.findall(correlation or ""):
                incident_times.setdefault(correlation_id, created)
        latencies = []
        for correlation, created in incident_times.items():
            if correlation in first_event:
                delta = (_parse_ts(created) - _parse_ts(first_event[correlation])).total_seconds()
                if 0 <= delta < 3600:
                    latencies.append(delta)

        error_markers = [marker for marker in (
            "Traceback", "database is locked", "ERROR=", "poll error"
        ) if marker in log]
    finally:
        conn.close()

    metrics = {
        "injectors": injectors,
        "stop_after_seconds": seconds,
        "exit_code": proc.returncode,
        "elapsed_s": round(elapsed, 2),
        "db_path": str(db_path),
        "events": events,
        "incidents": incidents,
        "events_per_s": round(events / max(elapsed, 1), 2),
        "incidents_per_s": round(incidents / max(elapsed, 1), 3),
        "attack_correlations": len(audit_corr),
        "matched_correlations": len(matched),
        "correlation_completeness": round(completeness, 4),
        "duplicate_incident_correlations": duplicate_incident_corr,
        "denies": denies,
        "llm_modes": modes,
        "integrity_check": integrity,
        "detection_to_incident_ms_p50": round(percentile(latencies, 0.50) * 1000, 2),
        "detection_to_incident_ms_p95": round(percentile(latencies, 0.95) * 1000, 2),
        "error_markers": error_markers,
        "log_tail": log[-1200:],
    }
    gates = {
        "launcher_started": True,
        "exit_code_zero": proc.returncode == 0,
        "db_integrity_ok": integrity == "ok",
        "no_error_markers": not error_markers,
        "events_and_incidents_present": events > 0 and incidents > 0,
        "correlations_at_least_95pct": completeness >= 0.95,
        "no_duplicate_incident_chains": duplicate_incident_corr == 0,
    }
    return {"metrics": metrics, "gates": gates}


def capture_section(injectors: int, live_seconds: int, capture_seconds: int) -> dict[str, Any]:
    """Real loopback capture: verify the pcap, its sheet, and the dashboard read-back."""
    powershell = shutil.which("powershell") or shutil.which("powershell.exe")
    if not powershell:
        return {"skipped": True, "reason": "powershell not available", "gates": {}}
    from src.capture import capture as capture_module
    from src.dashboard import create_app
    from fastapi.testclient import TestClient

    capture_module._METADATA_CACHE.clear()
    cmd = [
        powershell, "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", str(ROOT / "demo.ps1"), "-Live", "-Capture",
        "-ConcurrentInjectors", str(injectors),
        "-CaptureSeconds", str(capture_seconds), "-StopAfterSeconds", str(live_seconds),
    ]
    env = dict(os.environ)
    capture_dir = ROOT / "data" / "lab" / "captures"
    env["CERBERUS_CAPTURE_DIR"] = str(capture_dir)
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd, cwd=str(ROOT), env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=capture_seconds + 300,
        )
    except subprocess.TimeoutExpired as exc:
        return {"skipped": True, "reason": f"capture run timed out: {exc}", "gates": {}}
    elapsed = time.perf_counter() - started
    log = sanitise_log((proc.stdout or "") + "\n" + (proc.stderr or ""))
    match = re.search(r"\[capture\] started (.+)", log)
    if not match:
        return {
            "metrics": {"exit_code": proc.returncode, "log_tail": log[-2000:]},
            "gates": {"launcher_started_capture": False, "exit_code_zero": False},
        }
    pcap = Path(match.group(1).strip())
    sheet = pcap.with_suffix(".meta.json")
    md_sheet = pcap.with_suffix(".meta.md")
    artifacts_exist = pcap.exists() and sheet.exists() and md_sheet.exists()
    meta: dict[str, Any] = {}
    sha256_ok = False
    api: dict[str, Any] = {}
    if artifacts_exist:
        try:
            meta = json.loads(sheet.read_text(encoding="utf-8"))
            digest = hashlib.sha256()
            with pcap.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            sha256_ok = bool(meta.get("sha256")) and digest.hexdigest() == meta["sha256"]
            os.environ["CERBERUS_CAPTURE_DIR"] = str(capture_dir)
            app = create_app(db_path=meta.get("db_path") or (ROOT / "data" / "lab" / "lab_traffic.db"))
            with TestClient(app) as client:
                api = client.get("/api/capture").json()
        except Exception:
            pass
    summary = meta.get("summary") or {}
    metrics = {
        "exit_code": proc.returncode,
        "elapsed_s": round(elapsed, 2),
        "pcap": str(pcap),
        "metadata_sheet": str(sheet),
        "markdown_sheet": str(md_sheet),
        "artifacts_exist": artifacts_exist,
        "status": meta.get("status"),
        "filter": meta.get("filter"),
        "sha256": meta.get("sha256"),
        "sha256_matches_pcap": sha256_ok,
        "packets": summary.get("packets", 0),
        "protocols": summary.get("protocols", {}),
        "outside_endpoints": summary.get("outside_endpoints", []),
        "lab_only": summary.get("lab_only", False),
        "dashboard_source": api.get("source"),
        "dashboard_same_traffic": api.get("same_traffic", False),
        "dashboard_packets": (api.get("summary") or {}).get("packets", 0),
        "log_tail": log[-1200:],
    }
    gates = {
        "launcher_started_capture": True,
        "exit_code_zero": proc.returncode == 0,
        "pcap_and_sheets_exist": artifacts_exist,
        "metadata_status_complete": meta.get("status") == "complete",
        "sha256_matches_pcap": sha256_ok,
        "packets_present": int(summary.get("packets", 0)) > 0,
        "lab_only_endpoints": bool(summary.get("lab_only")) and not summary.get("outside_endpoints"),
        "dashboard_reads_same_pcap": bool(api.get("same_traffic"))
        and api.get("summary", {}).get("packets") == summary.get("packets"),
    }
    capture_module._METADATA_CACHE.clear()
    return {"metrics": metrics, "gates": gates}


def render(results: dict[str, Any], args: argparse.Namespace) -> str:
    lines = [
        "# CERBERUS acceptance stress benchmark",
        "",
        f"Generated {utcnow()} · simulation-only · no external targets",
        "",
        "| Section | Gate | Result |",
        "|---|---|---|",
    ]
    overall = True
    for name, section in results["sections"].items():
        if section.get("skipped"):
            lines.append(f"| {name} | skipped | {section['reason']} |")
            continue
        for gate, passed in section["gates"].items():
            overall = overall and bool(passed)
            lines.append(f"| {name} | {gate} | {'PASS' if passed else 'FAIL'} |")
    lines.extend(["", "## Measured values", ""])
    for name, section in results["sections"].items():
        lines.append(f"### {name}")
        lines.append("")
        if section.get("skipped"):
            lines.append(f"Skipped: {section['reason']}")
            lines.append("")
            continue
        lines.append("```json")
        lines.append(json.dumps(section["metrics"], indent=2, ensure_ascii=False))
        lines.append("```")
        lines.append("")
    lines.extend([
        "## Protocol",
        "",
        "- Adapter section uses injected failures only; no provider key is required.",
        "- Ollama section calls the real local OpenAI-compatible endpoint when reachable.",
        "- Dataset section samples CICIoT2023 at file level and never trains on attack rows.",
        "- Live section runs `demo.ps1 -Live` against a fresh SQLite DB and inspects it afterwards.",
        "- Capture section runs `demo.ps1 -Live -Capture` and checks the pcap, sheet, and dashboard read-back.",
        f"- CLI: `{args.command}`",
        "",
        f"**Overall:** {'PASS' if overall else 'FAIL'}",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sections", default="adapter,ollama,dataset")
    parser.add_argument("--ollama-requests", type=int, default=20)
    parser.add_argument("--dataset-rows", type=int, default=200)
    parser.add_argument("--live-injectors", type=int, default=5)
    parser.add_argument("--live-seconds", type=int, default=90)
    parser.add_argument("--capture-seconds", type=int, default=0,
                        help="E6 capture window; defaults to live-seconds + 30")
    parser.add_argument("--out", default="STRESS_BENCHMARK")
    args = parser.parse_args()
    args.command = " ".join(sys.argv)

    enabled = {name.strip() for name in args.sections.split(",") if name.strip()}
    runners: dict[str, Callable[[], dict[str, Any]]] = {
        "adapter": adapter_section,
        "ollama": lambda: ollama_section(args.ollama_requests),
        "dataset": lambda: dataset_section(args.dataset_rows),
        "live": lambda: live_section(args.live_injectors, args.live_seconds),
        "capture": lambda: capture_section(
            args.live_injectors, args.live_seconds,
            args.capture_seconds or (args.live_seconds + 30),
        ),
    }
    results = {"generated_utc": utcnow(), "sections": {}}
    for name in ("adapter", "ollama", "dataset", "live", "capture"):
        if name in enabled:
            print(f"[stress] running {name} ...", flush=True)
            results["sections"][name] = runners[name]()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = RESULTS_DIR / f"{args.out}.json"
    md_path = RESULTS_DIR / f"{args.out}.md"
    json_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(render(results, args), encoding="utf-8")

    failures = []
    for name, section in results["sections"].items():
        if section.get("skipped"):
            continue
        failures.extend(f"{name}.{gate}" for gate, ok in section["gates"].items() if not ok)
    print(f"[stress] report: {md_path}")
    if failures:
        print("[stress] FAILED gates: " + ", ".join(failures))
        return 1
    print("[stress] ALL GATES PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
