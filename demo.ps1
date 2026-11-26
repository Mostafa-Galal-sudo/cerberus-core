# ============================================================
#  Cerberus-Core  —  E2E Demo Script  (C3-T10)
#  Run: .\demo.ps1
#  Works in fallback mode (no API keys needed).
# ============================================================

$ErrorActionPreference = "Stop"
$Root  = $PSScriptRoot
$Venv  = "$Root\.venv\Scripts\python.exe"
$DB    = "$Root\data\lab\lab_traffic.db"
$Port  = 8000

function Write-Step { param([string]$msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$msg) Write-Host "    [OK] $msg"   -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "    [!!] $msg"   -ForegroundColor Yellow }

# ---- 0. Sanity checks -------------------------------------------------------
Write-Step "Cerberus-Core Demo — C3 Closed-Loop"
if (-not (Test-Path $Venv)) {
    Write-Error "Virtual env not found at $Venv. Run: python -m venv .venv && .venv\Scripts\pip install -e .[dev]"
    exit 1
}
if ($env:GROQ_API_KEY) { Write-Ok "GROQ_API_KEY detected — LLM mode (live)" }
else                    { Write-Warn "GROQ_API_KEY not set — running in deterministic fallback mode" }
if ($env:DEEPSEEK_API_KEY) { Write-Ok "DEEPSEEK_API_KEY detected" }

# ---- 1. Ensure DB directory exists ------------------------------------------
Write-Step "Preparing database"
New-Item -ItemType Directory -Force -Path (Split-Path $DB) | Out-Null
Write-Ok "DB path: $DB"

# ---- 2. Seed 60 s of normal traffic (in-process, no broker) ----------------
Write-Step "Seeding 60 seconds of normal IoT traffic (5 core devices)"
& $Venv -c @"
import sys, time
sys.path.insert(0, r'$Root')
from src.storage.db import open_db, save_event, utc_now
from src.simulator.devices import _CORE_PROFILES

conn = open_db(r'$DB')
import json, random
for i in range(300):                      # 300 events ~ 60 s of a 10-Hz mix
    p = random.choice(_CORE_PROFILES)
    save_event(conn, {
        'ts_utc':          utc_now(),
        'device_id':       p.device_id,
        'device_type':     p.device_type,
        'topic':           p.topics_publish[0],
        'qos':             p.qos,
        'payload_size':    random.randint(*p.payload_size_range),
        'payload_preview': json.dumps({'seq': i, 'demo': True}),
        'direction':       'publish',
    })
n = conn.execute('SELECT COUNT(*) FROM mqtt_events').fetchone()[0]
print(f'  Seeded {n} events into DB.')
"@
Write-Ok "Normal traffic seeded"

# ---- 3. Run the closed loop (3 attack → detect → defend cycles) -------------
Write-Step "Running 3 closed-loop cycles (attack → detect → defend)"
& $Venv -c @"
import sys, logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s %(name)s: %(message)s')
sys.path.insert(0, r'$Root')
from src.loop.runner import make_loop

events = []
lp = make_loop(db_path=r'$DB', on_event=events.append)
results = lp.run(cycles=3, interval=0.5, attack_count=20)

for r in results:
    atk = r.attack
    defense = r.defense
    iso_msg = ''
    if defense and defense.isolation and defense.isolation.executed:
        iso_msg = f'  ISOLATED: {defense.incident.device_id}'
    print(
        f'  Cycle {r.cycle}: attack={atk.mode} injected={atk.events_injected}'
        f'  detections={len(r.detections)}'
        f'  incident={defense.incident.id if defense else "none"}'
        f'  status={defense.incident.status if defense else "none"}'
        + iso_msg
    )

# Summary
total_inc = lp.incidents.conn.execute(\"SELECT COUNT(*) FROM incidents\").fetchone()[0]
total_ev  = lp.conn.execute(\"SELECT COUNT(*) FROM mqtt_events\").fetchone()[0]
print(f'\n  Total events in DB : {total_ev}')
print(f'  Total incidents    : {total_inc}')
print(f'  Callback events    : {len(events)}')
"@
Write-Ok "Closed-loop complete"

# ---- 4. Start the SOC dashboard (background) --------------------------------
Write-Step "Starting Cerberus SOC Dashboard on http://localhost:$Port"

$dashJob = Start-Job -ScriptBlock {
    param($venv, $root, $port, $db)
    Set-Location $root
    $env:CERBERUS_DB_PATH = $db
    & $venv -m uvicorn "src.dashboard:create_app" --factory --host 0.0.0.0 --port $port --no-access-log 2>&1
} -ArgumentList $Venv, $Root, $Port, $DB

# Give uvicorn 3 s to start
Start-Sleep 3

# Quick health check
try {
    $health = Invoke-RestMethod -Uri "http://localhost:$Port/api/health" -TimeoutSec 5
    Write-Ok "Dashboard live — total_events=$($health.total_events)  open_incidents=$($health.open_incidents)"
} catch {
    Write-Warn "Dashboard may still be starting. Check http://localhost:$Port manually."
}

# ---- 5. Done ----------------------------------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Cerberus-Core SOC Dashboard:" -ForegroundColor White
Write-Host "    http://localhost:$Port" -ForegroundColor Yellow
Write-Host ""
Write-Host "  API endpoints:" -ForegroundColor White
Write-Host "    /api/health      — system health + KPIs" -ForegroundColor Gray
Write-Host "    /api/overview    — device grid + KPIs" -ForegroundColor Gray
Write-Host "    /api/incidents   — all incidents" -ForegroundColor Gray
Write-Host "    /api/isolations  — isolation registry" -ForegroundColor Gray
Write-Host "    /api/audit       — policy audit log" -ForegroundColor Gray
Write-Host "    /api/stream      — SSE live feed" -ForegroundColor Gray
Write-Host ""
Write-Host "  Press Ctrl+C to stop the dashboard." -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Keep script alive until Ctrl+C, then clean up
try {
    while ($true) {
        Start-Sleep 2
        # Print job output lines as they arrive
        Receive-Job $dashJob | ForEach-Object { Write-Host "  [dash] $_" -ForegroundColor DarkGray }
    }
} finally {
    Stop-Job  $dashJob -ErrorAction SilentlyContinue
    Remove-Job $dashJob -ErrorAction SilentlyContinue
    Write-Host "`nDashboard stopped." -ForegroundColor Yellow
}
