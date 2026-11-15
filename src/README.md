# src/

All CERBERUS source code, one package per layer of the architecture:

```
src/
├── simulator/   simulated IoT traffic generation (Checkpoint 1)
├── storage/     SQLite persistence layer (Checkpoint 1)
├── detection/   rules + ML + fingerprinting + hybrid combiner (Checkpoint 2)
├── agents/      defense (Groq) + attack (DeepSeek) LLM agents (Checkpoint 3)
├── policy/      response allowlist, scope rules, audit log (Checkpoint 3)
├── response/    automated isolation actions (Checkpoint 3)
├── incidents/   incident schema + timeline model (Checkpoint 3)
├── dashboard/   SOC-style web dashboard (Checkpoints 3-5)
├── capture/     packet capture pipeline for the real testbed (Checkpoint 4)
├── attacks/     protocol + RF attack implementations (Checkpoint 4)
├── evaluation/  benchmark harness + statistical evaluation (Checkpoints 2+5)
└── notebooks/   exploratory Jupyter notebooks (Checkpoint 1)
```

Architecture rule: the detection, agents, and response layers communicate only
through the policy layer — no component executes privileged actions directly.
