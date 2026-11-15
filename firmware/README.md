# firmware/

ESP32 device firmware for the physical testbed (Checkpoint 4, task C4-T01).

Planned sketches:
- `temp_sensor/` — MQTT client publishing per its `DeviceProfile` pattern
- `motion_sensor/` — event-driven publisher
- `smart_plug/` — power telemetry publisher
- `attacker/` — attack-generation firmware using `esp_wifi_80211_tx()`
  (deauth module, used only inside the shielded enclosure)

Firmware must mirror the simulator's device profiles so the detection engine
behaves identically on simulated and real traffic.
