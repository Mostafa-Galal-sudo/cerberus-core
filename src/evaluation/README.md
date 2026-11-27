# src/evaluation/

Benchmark harness and statistical evaluation (Checkpoint 2 task C2-T07,
Checkpoint 5 task C5-T03).

Planned files:
- `benchmark.py` — one-command comparison: rules-only vs ML-only vs hybrid,
  identical leakage-free splits, metrics (accuracy/precision/recall/FPR/F1)
  + confusion matrices
- `stats.py` — bootstrap confidence intervals for lab-collected results
  (the proposal explicitly requires CIs, not point estimates)
- `gap_report.py` — CICIoT2023 vs lab side-by-side comparison (C4-T09)

`stress_benchmark.py` is the acceptance harness: four gated sections (`adapter`, `ollama`,
`dataset`, `live`) with hard failures instead of soft warnings. It writes
`results/STRESS_BENCHMARK.md/.json`. Run executables from the repo root with the virtualenv
Python; example:

```powershell
& .\.venv\Scripts\python.exe src/evaluation/stress_benchmark.py --sections adapter,ollama,dataset,live --ollama-requests 20 --dataset-rows 200 --live-injectors 5 --live-seconds 90
```

The `live` section invokes `demo.ps1 -Live` against a fresh lab DB and redacts the dashboard
release token from captured logs. No hosted key is needed.

All numeric results published in `results/` must be reproducible from here.
