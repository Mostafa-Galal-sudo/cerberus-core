# tests/

pytest suite. Every checkpoint ships with its tests green
(`pytest tests/ -v` is part of the weekly evidence pack, task WK-T04).

Planned files:
- `test_traffic_gen.py` — events written for all devices, schema correct (C1-T07)
- `test_features.py`, `test_rules_engine.py`, `test_hybrid.py` (Checkpoint 2)
- `test_policy.py` — deny-by-default behavior, no bypass path (Checkpoint 3)
- `test_fallback.py` — deterministic behavior when LLM APIs fail (C3-T09)
