# src/attacks/

Attack implementations used by the attack agent and the lab campaign
(Checkpoint 4, tasks C4-T05, C4-T07).

Planned files:
- `mqtt_flood.py` — MQTT flooding from testbed endpoints
- `mqtt_inject.py` — publish injection / spoofed device identity
- `deauth.py` — 802.11 deauth/disassociation via `esp_wifi_80211_tx()`
  (proposal refs [4], [5])

Legal/safety constraint: RF attacks run only inside the isolated/shielded
enclosure (Checkpoint 6) — see Risks section of the proposal (NTRA regulation).
Protocol-layer attacks run only against the isolated lab testbed.
