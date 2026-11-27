param(
    [switch]$Live,
    [int]$LiveBaselineSpan = 180,
    [int]$LiveAttackInterval = 20,
    [int]$LiveAttackCount = 20,
    [int]$LiveWorkerInterval = 2,
    [int]$LiveCooldown = 30,
    [int]$StopAfterSeconds = 0
)

# ============================================================
#  Cerberus-Core  --  E2E Demo Script  (C3-T10)
#  Run: .\demo.ps1            -> 3 closed-loop cycles (C3 default)
#       .\demo.ps1 -Live      -> E1 continuous simulated SOC
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

$BrokerHost = "127.0.0.1"
$BrokerPort = 1883
$liveProcs  = @()

if ($Live) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $DB = Join-Path $Root "data\lab\live_traffic_$stamp.db"
}

function Write-Step { param([string]$msg) Write-Host "" ; Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$msg) Write-Host "    [OK] $msg"  -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "    [!!] $msg"  -ForegroundColor Yellow }

function Start-LiveProc {
    param([string]$Name, [string[]]$PythonArgs)
    $out = Join-Path $env:TEMP "cerberus_live_${Name}.out.log"
    $err = Join-Path $env:TEMP "cerberus_live_${Name}.err.log"
    Remove-Item $out, $err -Force -ErrorAction SilentlyContinue
    $proc = Start-Process -FilePath $Venv -PassThru -WindowStyle Hidden `
        -WorkingDirectory $Root -ArgumentList $PythonArgs `
        -RedirectStandardOutput $out -RedirectStandardError $err
    $entry = [pscustomobject]@{ Name = $Name; Proc = $proc; Out = $out; Err = $err }
    $script:liveProcs += $entry
    return $entry
}

function Wait-LogLine {
    param([string]$Log, [string]$Pattern, [string]$Name, [int]$Timeout = 25)
    if ([string]::IsNullOrWhiteSpace($Log)) {
        Write-Warn "No log path supplied while waiting for $Name"
        return $false
    }
    for ($i = 0; $i -lt $Timeout; $i++) {
        if ((Test-Path $Log) -and (Select-String -Path $Log -Pattern $Pattern -SimpleMatch -Quiet)) {
            return $true
        }
        Start-Sleep 1
    }
    Write-Warn "Timed out waiting for '$Pattern' from $Name (log: $Log)"
    return $false
}

function Stop-LiveProcs {
    foreach ($entry in $script:liveProcs) {
        if ($entry.Proc -and -not $entry.Proc.HasExited) {
            Stop-Process -Id $entry.Proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---- 0. Sanity checks -------------------------------------------------------
if ($Live) { Write-Step "Cerberus-Core E1 -- Live Simulated SOC" }
else       { Write-Step "Cerberus-Core Demo -- C3 Closed-Loop" }
if (-not (Test-Path $Venv)) {
    Write-Error "Virtual env not found at $Venv. Create it with: python -m venv .venv"
    exit 1
}
if ($env:GROQ_API_KEY)     { Write-Ok   "GROQ_API_KEY detected -- LLM mode (live)" }
else                        { Write-Warn "GROQ_API_KEY not set -- running deterministic fallback mode" }
if ($env:DEEPSEEK_API_KEY) { Write-Ok   "DEEPSEEK_API_KEY detected" }

if ($Live) {
    $brokerSvc = Get-Service -Name mosquitto -ErrorAction SilentlyContinue
    if ($brokerSvc -and $brokerSvc.Status -ne "Running") {
        try { Start-Service -Name mosquitto -ErrorAction Stop }
        catch { Write-Error "Cannot start Mosquitto service: $($_.Exception.Message)"; exit 1 }
    }
    try {
        $probe = New-Object System.Net.Sockets.TcpClient
        $probe.Connect($BrokerHost, $BrokerPort)
        $probe.Close()
    } catch {
        Write-Error "Mosquitto broker not reachable at ${BrokerHost}:${BrokerPort}. Start the broker and retry."
        exit 1
    }
    Write-Ok "Mosquitto broker reachable at ${BrokerHost}:${BrokerPort}"
    Write-Ok "Fresh live DB: $DB"
}

# ---- 1. Ensure DB directory exists ------------------------------------------
Write-Step "Preparing database"
$dbDir = Split-Path $DB
New-Item -ItemType Directory -Force -Path $dbDir | Out-Null
Write-Ok "DB path: $DB"

if ($Live) {
    # ---- E1 live pipeline: subscriber -> seed -> publisher -> worker -> injector ----
    $env:CERBERUS_DB_PATH = $DB

    Write-Step "Starting MQTT telemetry subscriber (sole DB writer)"
    $sub = Start-LiveProc -Name subscriber -PythonArgs @(
        '-m', 'src.live.subscriber', '--db', $DB, '--host', $BrokerHost, '--port', "$BrokerPort"
    )
    if (-not (Wait-LogLine $sub.Out '[subscriber] ready' 'subscriber')) { Stop-LiveProcs; exit 1 }
    Write-Ok "Subscriber ready, DB=$DB"

    Write-Step "Publishing benign baseline over MQTT ($LiveBaselineSpan s of UTC timestamps)"
    $seedOut = & $Venv -m src.live.publisher --mode seed --db $DB --host $BrokerHost --port $BrokerPort `
        --count 300 --span $LiveBaselineSpan 2>&1
    $seedOut | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { Write-Error "Baseline seed publisher failed"; Stop-LiveProcs; exit 1 }
    $seedText = $seedOut | Out-String
    $expectedBaseline = 0
    if ($seedText -match 'published=(\d+)') { $expectedBaseline = [int]$Matches[1] }
    $baseline = 0
    for ($i = 0; $i -lt 15; $i++) {
        $baseline = [int](& $Venv -c "import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute('select count(*) from mqtt_events').fetchone()[0])" $DB)
        if ($baseline -ge $expectedBaseline -and $expectedBaseline -gt 0) { break }
        Start-Sleep 1
    }
    if ($baseline -lt $expectedBaseline) { Write-Warn "Only $baseline of $expectedBaseline baseline rows arrived; continuing anyway" }
    else { Write-Ok "Baseline rows persisted by subscriber: $baseline" }

    Write-Step "Starting continuous simulated publisher"
    $pub = Start-LiveProc -Name publisher -PythonArgs @(
        '-m', 'src.live.publisher', '--mode', 'continuous', '--db', $DB,
        '--host', $BrokerHost, '--port', "$BrokerPort"
    )
    if (-not (Wait-LogLine $pub.Out '[gen]' 'publisher')) { Stop-LiveProcs; exit 1 }
    Write-Ok "Publisher running with real MQTT socket"

    Write-Step "Starting detection worker on subscriber-written telemetry"
    $worker = Start-LiveProc -Name worker -PythonArgs @(
        '-m', 'src.live.worker', '--db', $DB, '--interval', "$LiveWorkerInterval",
        '--cooldown', "$LiveCooldown"
    )
    if (-not (Wait-LogLine $worker.Out '[worker] ready' 'worker')) { Stop-LiveProcs; exit 1 }
    Write-Ok "Detection worker ready"

    Write-Step "Starting policy-bounded anomaly injector (every $LiveAttackInterval s)"
    $inj = Start-LiveProc -Name injector -PythonArgs @(
        '-m', 'src.live.injector', '--db', $DB, '--host', $BrokerHost,
        '--port', "$BrokerPort", '--interval', "$LiveAttackInterval", '--count', "$LiveAttackCount"
    )
    if (-not (Wait-LogLine $inj.Out '[injector] ready' 'injector')) { Stop-LiveProcs; exit 1 }
    Write-Ok "Anomaly injector running: flood -> bloat -> rogue"
} else {
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
}

# ---- 4. Start the SOC dashboard (background) --------------------------------
Write-Step "Starting Cerberus SOC Dashboard on http://127.0.0.1:$Port"

# A failed previous run can leave a uvicorn child listening on the port.
$stalePids = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
             Select-Object -ExpandProperty OwningProcess -Unique
foreach ($stalePid in $stalePids) {
    $staleProc = Get-CimInstance Win32_Process -Filter "ProcessId=$stalePid" -ErrorAction SilentlyContinue
    if ($staleProc -and $staleProc.CommandLine -like "*src.dashboard:create_app*" -and $staleProc.CommandLine -like "*$Venv*") {
        Write-Warn "Stopping stale demo dashboard (PID $stalePid) on port $Port"
        Stop-Process -Id $stalePid -Force -ErrorAction SilentlyContinue
        Start-Sleep 1
    } elseif ($staleProc) {
        Write-Error "Port $Port is in use by PID $stalePid ($($staleProc.Name)). Set CERBERUS_PORT to another port."
        exit 1
    }
}

$dashOut = Join-Path $env:TEMP "cerberus_dashboard.out.log"
$dashErr = Join-Path $env:TEMP "cerberus_dashboard.err.log"
Remove-Item $dashOut, $dashErr -Force -ErrorAction SilentlyContinue
$dashProc = $null

# The child inherits both variables; H3 requires the release token at startup.
$env:CERBERUS_DB_PATH = $DB
$env:CERBERUS_DASHBOARD_TOKEN = $Token

try {
    $dashProc = Start-Process -FilePath $Venv -PassThru -WindowStyle Hidden `
        -WorkingDirectory $Root `
        -ArgumentList @('-m', 'uvicorn', 'src.dashboard:create_app', '--factory', '--host', '127.0.0.1', '--port', "$Port", '--no-access-log') `
        -RedirectStandardOutput $dashOut -RedirectStandardError $dashErr

    # Use 127.0.0.1, not "localhost": on IPv6-first hosts localhost resolves to
    # ::1, uvicorn binds IPv4 only, and Invoke-RestMethod does not fall back.
    $healthUrl = "http://127.0.0.1:$Port/api/health"
    $ready = $false
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep 1
        try {
            $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 3
            $ready = $true
            break
        } catch {
            if ($dashProc.HasExited) { break }
        }
    }
    if (-not $ready) {
        Write-Host "    [debug] dashboard stdout:" -ForegroundColor DarkGray
        if (Test-Path $dashOut) { Get-Content $dashOut -Tail 12 }
        Write-Host "    [debug] dashboard stderr:" -ForegroundColor DarkGray
        if (Test-Path $dashErr) { Get-Content $dashErr -Tail 12 }
        Write-Error "Dashboard failed health check on $healthUrl"
        exit 1
    }
    $runMode = if ($Live) { "E1 live simulated SOC" } else { "C3 closed-loop demo" }
    Write-Ok "Dashboard live ($runMode) -- total_events=$($health.total_events)  open_incidents=$($health.open_incidents)"
    Write-Ok "Release token (X-Cerberus-Token): $Token"

    # ---- 5. Done ------------------------------------------------------------
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Cerberus SOC Dashboard:  http://127.0.0.1:$Port"          -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  API endpoints:"                                            -ForegroundColor White
    Write-Host "    /api/health      -- system health + KPIs"               -ForegroundColor Gray
    Write-Host "    /api/overview    -- device grid + KPIs"                 -ForegroundColor Gray
    Write-Host "    /api/incidents   -- all incidents"                       -ForegroundColor Gray
    Write-Host "    /api/isolations  -- isolation registry"                  -ForegroundColor Gray
    Write-Host "    /api/audit       -- policy audit log"                    -ForegroundColor Gray
    Write-Host "    /api/stream      -- SSE live feed"                       -ForegroundColor Gray
    Write-Host ""
    if ($Live) {
        Write-Host "  Live DB: $DB"                                            -ForegroundColor Gray
        Write-Host "  Component logs: $env:TEMP\cerberus_live_*.out.log"        -ForegroundColor Gray
        Write-Host "  Press Ctrl+C to stop the entire simulated SOC."         -ForegroundColor White
    } else {
        Write-Host "  Press Ctrl+C to stop the dashboard."                    -ForegroundColor White
    }
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    $startedAt = Get-Date
    while ($true) {
        if ($StopAfterSeconds -gt 0 -and ((Get-Date) - $startedAt).TotalSeconds -ge $StopAfterSeconds) {
            Write-Warn "StopAfterSeconds=$StopAfterSeconds reached; shutting down live run"
            break
        }
        Start-Sleep 2
    }
} finally {
    if ($dashProc) {
        try {
            Get-CimInstance Win32_Process |
                Where-Object { $_.ParentProcessId -eq $dashProc.Id } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
            Stop-Process -Id $dashProc.Id -Force -ErrorAction SilentlyContinue
        } catch {
        }
    }
    Stop-LiveProcs
    if ($Live) {
        Start-Sleep 1
        try {
            $summary = & $Venv -m src.live.summary --db $DB
            Write-Host "  Live run summary: $summary" -ForegroundColor Yellow
        } catch {
            Write-Warn "Could not read live DB summary: $($_.Exception.Message)"
        }
    }
    Write-Host ""
    Write-Host "Dashboard stopped." -ForegroundColor Yellow
}
