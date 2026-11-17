# demo.ps1 — CERBERUS Checkpoint 1 live demo launcher
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\demo.ps1
#   powershell -ExecutionPolicy Bypass -File .\demo.ps1 -Duration 600
#
# Opens 4 windows:
#   T1 broker      : mosquitto -c mosquitto.conf -v
#   T2 viewer      : mosquitto_sub -t 'lab/#' -v   (also shows retained status at start)
#   T3 generator   : traffic_gen --duration N      (prints summary JSON when it ends)
#   T4 control     : ENTER toggles the plug, S prints DB summary, Q quits

param(
    [int]$Duration = 300
)

$ErrorActionPreference = 'Stop'

$repo    = 'F:\UserData\Downloads\Cerberus\cerberus-core'
$mosqDir = 'C:\Program Files\mosquitto'
$mosq    = Join-Path $mosqDir 'mosquitto.exe'
$sub     = Join-Path $mosqDir 'mosquitto_sub.exe'
$pub     = Join-Path $mosqDir 'mosquitto_pub.exe'
$py      = Join-Path $repo '.venv\Scripts\python.exe'
$conf    = Join-Path $repo 'mosquitto.conf'
$db      = Join-Path $repo 'data\lab\lab_traffic.db'

# ---------- pre-flight ----------
$missing = @($mosq, $sub, $pub, $py) | Where-Object { -not (Test-Path $_) }
if ($missing) {
    Write-Host "[X] missing files:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "    $_" }
    exit 1
}
if (-not (Test-Path (Join-Path $repo 'requirements.txt'))) {
    Write-Host "[X] repo not found at $repo" -ForegroundColor Red
    exit 1
}

# is something already listening on 1883?
$portBusy = $false
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $async = $tcp.BeginConnect('127.0.0.1', 1883, $null, $null)
    if ($async.AsyncWaitHandle.WaitOne(500)) { $portBusy = $tcp.Connected }
    $tcp.Close()
} catch { }

function Start-Term {
    param([string]$Title, [string]$Command)
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
    Start-Process powershell -WorkingDirectory $repo -ArgumentList @('-NoExit', '-EncodedCommand', $enc) | Out-Null
    Write-Host "[+] opened: $Title"
}

# ---------- T1: broker ----------
if ($portBusy) {
    Write-Host "[!] port 1883 already busy, assuming broker is already running, skipping T1"
} else {
    if (Test-Path $conf) {
        Start-Term 'T1 broker (mosquitto.conf)' "& '$mosq' -c '$conf' -v"
    } else {
        Write-Host "[!] mosquitto.conf not found in repo, starting broker without -c"
        Start-Term 'T1 broker (no conf)' "& '$mosq' -v"
    }
    Start-Sleep -Seconds 2
}

# ---------- T2: live viewer ----------
Start-Term 'T2 viewer (lab/#)' "& '$sub' -t 'lab/#' -v"
Start-Sleep -Milliseconds 500

# ---------- T3: traffic generator ----------
Start-Term "T3 generator ($Duration s)" "& '$py' -m src.simulator.traffic_gen --duration $Duration"

# ---------- T4: interactive control ----------
# Single-quoted here-string + placeholders, so nothing is interpolated here;
# every __TOKEN__ is replaced with a real path below.
$ctrlTemplate = @'
$pub  = '__PUB__'
$py   = '__PY__'
$repo = '__REPO__'
$db   = '__DB__'
Write-Host 'ENTER = toggle plug    S = DB summary    Q = quit' -ForegroundColor Cyan
while ($true) {
    $k = (Read-Host '>').Trim().ToLower()
    if ($k -eq 'q') { break }
    elseif ($k -eq 's') {
        & $py -c 'import json,sys; sys.path.insert(0,"__REPO_F__"); from src.storage import db; print(json.dumps(db.summarize(db.open_db("__DB_F__")), indent=2))'
    }
    else {
        & $pub -t 'lab/room1/cmd' -m '{"action":"toggle"}' -q 1
        Write-Host '-> toggle sent (plug publishes within 14-16 s, watch plug_state + power jump)'
    }
}
'@

$repl = [ordered]@{
    '__PUB__'    = $pub
    '__PY__'     = $py
    '__REPO_F__' = ($repo -replace '\\', '/')
    '__DB_F__'   = ($db -replace '\\', '/')
    '__REPO__'   = $repo
    '__DB__'     = $db
}
$ctrl = $ctrlTemplate
foreach ($k in $repl.Keys) { $ctrl = $ctrl.Replace($k, $repl[$k]) }

Start-Term 'T4 control' $ctrl

Write-Host ''
Write-Host "Demo launched. Generator window closes its run after $Duration s and prints the summary."
Write-Host 'Close each window manually when done (T4: press Q to exit its loop).'
