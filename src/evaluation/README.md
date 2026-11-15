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

All numeric results published in `results/` must be reproducible from here.
