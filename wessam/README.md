[README_C3.md](https://github.com/user-attachments/files/35511717/README_C3.md)

# CERBERUS — Checkpoint 3 (agents + response + dashboard-ready incidents, simulated end-to-end)

Copy into cerberus-core (merge with existing folders): `src/policy, src/incidents, src/agents, src/attacks, src/response, src/pipeline.py`, `run_demo.py`, `tests/`, `pytest.ini`, `requirements.txt`, `.env.example`.

| Task | Where |
|---|---|
| C3-T01 policy | `src/policy/` (`allowlist.yaml`, `engine.py`) |
| C3-T02 evidence tools | `src/agents/tools/evidence.py` |
| C3-T03 incidents | `src/incidents/` |
| C3-T04 defense agent (Groq) | `src/agents/defense_agent.py` (+ offline `RuleBasedDefenseAgent`) |
| C3-T05 attack agent (DeepSeek) | `src/agents/attack_agent.py`, `src/attacks/` |
| C3-T06 response layer | `src/response/executor.py` |

Run: `pip install -r requirements.txt && python run_demo.py [flood|injection|spoof|all] [--llm]` and `pytest`.
`--llm` uses Groq/DeepSeek if keys are in `.env` (copy `.env.example`); otherwise offline agents run.

Adapter points to your real work: `stand_in_detector` in run_demo.py -> your IDS in `src/detection`;
file formats read by `evidence.py` (mqtt_log.jsonl / features.jsonl / baseline.json / pcap) -> your C2 outputs;
`SimWorld` -> replaced later by the real testbed.
