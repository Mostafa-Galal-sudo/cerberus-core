param([string]$Duration = 300)

$root = $PSScriptRoot
Set-Location $root

$mosqDir = "C:\Program Files\mosquitto"
if (-not (Test-Path "$mosqDir\mosquitto.exe")) {
    Write-Host "Mosquitto not found at $mosqDir - fix MOSQ_DIR in this script." -ForegroundColor Red
    exit 1
}

function Start-DemoTerm($title, $command) {
    $bytes = [Text.Encoding]::Unicode.GetBytes($command)
    $enc = [Convert]::ToBase64String($bytes)
    if (Get-Command wt.exe -ErrorAction SilentlyContinue) {
        Start-Process wt.exe -ArgumentList "-d `"$root`" powershell -NoExit -EncodedCommand $enc"
    } else {
        Start-Process powershell -WorkingDirectory $root -ArgumentList "-NoExit", "-EncodedCommand", $enc
    }
    Start-Sleep -Milliseconds 400
}

Start-DemoTerm "broker" "& '$mosqDir\mosquitto.exe' -c .\mosquitto.conf -v"
Start-DemoTerm "viewer" "& '$mosqDir\mosquitto_sub.exe' -t 'lab/#' -v"
Start-DemoTerm "generator" ".\.venv\Scripts\python.exe -m src.simulator.traffic_gen --duration $Duration"
Start-DemoTerm "control" ".\scripts\toggle-plug.ps1"

Write-Host ""
Write-Host "4 demo terminals opened." -ForegroundColor Green
Write-Host "  T1 broker      T2 viewer (lab/#)"
Write-Host "  T3 generator ($Duration s)"
Write-Host "  T4 press enter each time to toggle the plug"
Write-Host "DB summary any time:  .\scripts\db-summary.ps1"
