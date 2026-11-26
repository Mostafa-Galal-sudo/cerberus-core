# ============================================================
#  Cerberus-Core  --  E2E Demo Script  (C3-T10)
#  Run: .\demo.ps1
#  Works in fallback mode (no API keys needed).
# ============================================================

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Venv = Join-Path $Root ".venv\Scripts\python.exe"
$DB   = Join-Path $Root "data\lab\lab_traffic.db"
$Port = if ($env:CERBERUS_PORT) { [int]$env:CERBERUS_PORT } else { 8000 }
$TokenBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($TokenBytes)
$Token = [Convert]::ToBase64String($TokenBytes)

function Write-Step { param([string]$msg) Write-Host "" ; Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$msg) Write-Host "    [OK] $msg"  -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "    [!!] $msg"  -ForegroundColor Yellow }

# ---- 0. Sanity checks -------------------------------------------------------
Write-Step "Cerberus-Core Demo -- C3 Closed-Loop"
if (-not (Test-Path $Venv)) {
    Write-Error "Virtual env not found at $Venv. Create it with: python -m venv .venv"
    exit 1
}
if ($env:GROQ_API_KEY)     { Write-Ok   "GROQ_API_KEY detected -- LLM mode (live)" }
else                        { Write-Warn "GROQ_API_KEY not set -- running deterministic fallback mode" }
if ($env:DEEPSEEK_API_KEY) { Write-Ok   "DEEPSEEK_API_KEY detected" }

# ---- 1. Ensure DB directory exists ------------------------------------------
Write-Step "Preparing database"
$dbDir = Split-Path $DB
New-Item -ItemType Directory -Force -Path $dbDir | Out-Null
Write-Ok "DB path: $DB"

# ---- 2. Write Python seed script to temp file and run it -------------------
Write-Step "Seeding 60 seconds of normal IoT traffic (5 core devices)"

$seedScript = Join-Path $env:TEMP "cerberus_seed.py"
Set-Content -Path $seedScript -Encoding UTF8 -Value @'
import sys, json, random
sys.path.insert(0, ROOT)
from src.storage.db import open_db, save_event, utc_now
from src.simulator.devices import _CORE_PROFILES

conn = open_db(DB_PATH)
for i in range(300):
    p = random.choice(_CORE_PROFILES)
    save_event(conn, {
        "ts_utc":          utc_now(),
        "device_id":       p.device_id,
        "device_type":     p.device_type,
        "topic":           p.topics_publish[0],
        "qos":             p.qos,
        "payload_size":    random.randint(*p.payload_size_range),
        "payload_preview": json.dumps({"seq": i, "demo": True}),
        "direction":       "publish",
    })
n = conn.execute("SELECT COUNT(*) FROM mqtt_events").fetchone()[0]
print(f"  Seeded {n} events into DB.")
'@

# Prepend ROOT and DB_PATH assignments using PowerShell variable expansion
$header = "ROOT = r'$Root'" + "`nDB_PATH = r'$DB'"
$body   = Get-Content $seedScript -Raw
Set-Content -Path $seedScript -Encoding UTF8 -Value ($header + "`n" + $body)

& $Venv $seedScript
Write-Ok "Normal traffic seeded"

# ---- 3. Write loop script to temp file and run it --------------------------
Write-Step "Running 3 closed-loop cycles (attack -> detect -> defend)"

$loopScript = Join-Path $env:TEMP "cerberus_loop.py"
Set-Content -Path $loopScript -Encoding UTF8 -Value @'
import sys, logging
logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
sys.path.insert(0, ROOT)
from src.loop.runner import make_loop

events = []
lp = make_loop(db_path=DB_PATH, on_event=events.append)
results = lp.run(cycles=3, interval=0.5, attack_count=20)

for r in results:
    atk     = r.attack
    defense = r.defense
    iso_msg = ""
    if defense and defense.isolation and defense.isolation.executed:
        iso_msg = f"  ISOLATED: {defense.incident.device_id}"
    print(
        f"  Cycle {r.cycle}:"
        f"  attack={atk.mode if atk else 'err'}"
        f"  injected={atk.events_injected if atk else 0}"
        f"  detections={len(r.detections)}"
        f"  incident={defense.incident.id if defense else 'none'}"
        f"  status={defense.incident.status if defense else 'none'}"
        + iso_msg
    )

total_inc = lp.incidents.conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
total_ev  = lp.conn.execute("SELECT COUNT(*) FROM mqtt_events").fetchone()[0]
print(f"\n  Total events in DB : {total_ev}")
print(f"  Total incidents    : {total_inc}")
print(f"  Callback events    : {len(events)}")
'@

$header2 = "ROOT = r'$Root'" + "`nDB_PATH = r'$DB'"
$body2   = Get-Content $loopScript -Raw
Set-Content -Path $loopScript -Encoding UTF8 -Value ($header2 + "`n" + $body2)

& $Venv $loopScript
Write-Ok "Closed-loop complete"

# ---- 4. Start the SOC dashboard (background) --------------------------------
Write-Step "Starting Cerberus SOC Dashboard on http://localhost:$Port"

$dashJob = Start-Job -ScriptBlock {
    param($venv, $root, $port, $token, $db)
    Set-Location $root
    $env:CERBERUS_DB_PATH = $db
    $env:CERBERUS_DASHBOARD_TOKEN = $token
    & $venv -m uvicorn "src.dashboard:create_app" --factory --host 127.0.0.1 --port $port --no-access-log
} -ArgumentList $Venv, $Root, $Port, $Token, $DB

$ready = $false
for ($i = 0; $i -lt 12; $i++) {
    Start-Sleep 1
    try {
        $health = Invoke-RestMethod -Uri "http://localhost:$Port/api/health" -TimeoutSec 3
        $ready = $true
        break
    } catch {
    }
}
if (-not $ready) {
    Write-Error "Dashboard failed health check on http://localhost:$Port"
    Stop-Job $dashJob -ErrorAction SilentlyContinue
    Remove-Job $dashJob -ErrorAction SilentlyContinue
    exit 1
}
Write-Ok "Dashboard live -- total_events=$($health.total_events)  open_incidents=$($health.open_incidents)"
Write-Ok "Release token (X-Cerberus-Token): $Token"

# ---- 5. Done ----------------------------------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Cerberus SOC Dashboard:  http://localhost:$Port"           -ForegroundColor Yellow
Write-Host ""
Write-Host "  API endpoints:"                                             -ForegroundColor White
Write-Host "    /api/health      -- system health + KPIs"                -ForegroundColor Gray
Write-Host "    /api/overview    -- device grid + KPIs"                  -ForegroundColor Gray
Write-Host "    /api/incidents   -- all incidents"                        -ForegroundColor Gray
Write-Host "    /api/isolations  -- isolation registry"                   -ForegroundColor Gray
Write-Host "    /api/audit       -- policy audit log"                     -ForegroundColor Gray
Write-Host "    /api/stream      -- SSE live feed"                        -ForegroundColor Gray
Write-Host ""
Write-Host "  Press Ctrl+C to stop the dashboard."                       -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

try {
    while ($true) {
        Start-Sleep 2
        Receive-Job $dashJob 2>$null | ForEach-Object { Write-Host "  [dash] $_" -ForegroundColor DarkGray }
    }
} finally {
    Stop-Job   $dashJob -ErrorAction SilentlyContinue
    Remove-Job $dashJob -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host "Dashboard stopped." -ForegroundColor Yellow
}
