# src/capture/

Packet capture pipeline for the real testbed (Checkpoint 4, task C4-T03).

Planned files:
- `capture_runner.py` — dumpcap/tshark rolling captures, UTC filenames
- `pcap_index.py` — index captures for fast evidence lookup

Used to build `data/lab/` (normal baseline + labeled attacks) and to serve
PCAP evidence to the defense agent.
