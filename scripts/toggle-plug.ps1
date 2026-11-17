$mosqPub = "C:\Program Files\mosquitto\mosquitto_pub.exe"
while ($true) {
    Read-Host "Press Enter to toggle the plug (or Ctrl+C to stop)" | Out-Null
    & $mosqPub -t "lab/room1/cmd" -m '{"action":"toggle"}' -q 1
    Write-Host "-> toggle sent to lab/room1/cmd" -ForegroundColor Yellow
}
