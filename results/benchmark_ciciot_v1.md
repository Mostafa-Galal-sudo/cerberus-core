# CICIoT2023 benchmark — detection engine v1

Generated 2026-11-26 14:51 UTC · dataset `data\raw\ciciot2023\CSV` (309 capture files) · seed 0

## Protocol

- One feature pipeline for every detector: the 39 numeric CICIoT2023 features, constant columns dropped once over the sampled data.
- Training uses benign traffic only. No attack row is ever shown to any detector during fitting.
- Alarm thresholds are fixed a priori from the benign training distribution (99.5% quantile for the deviation baseline, contamination 0.5% for the Isolation Forest). Nothing is tuned on the test partition.
- Benign captures are split at file level: whole capture files go to training or to testing, so no capture contributes rows to both sides.
- The per-device behavioural fingerprint is not applied here: CICIoT2023 rows carry no device identity. It is validated on the lab MQTT data instead (C2-T09).

## Partitions

| split | rows | contents |
|---|---|---|
| train | 440,245 | 2 benign capture files |
| test | 1,267,198 | 657,946 benign rows + 609,252 attack rows across 7 categories, 307 files |

Feature columns: 39 · baseline limit 1.877 · Isolation Forest limit 0.582

## Headline metrics (test partition)

| detector | precision | recall | f1 | fpr | accuracy | tp | fp | fn | tn |
|---|---|---|---|---|---|---|---|---|---|
| rules | 0.961 | 0.955 | 0.958 | 0.036 | 0.960 | 582096 | 23720 | 27156 | 634226 |
| rules_strict | 0.996 | 0.282 | 0.439 | 0.001 | 0.654 | 171750 | 642 | 437502 | 657304 |
| iforest | 0.962 | 0.440 | 0.604 | 0.016 | 0.723 | 268271 | 10536 | 340981 | 647410 |
| baseline | 0.994 | 0.867 | 0.926 | 0.005 | 0.934 | 528503 | 3398 | 80749 | 654548 |
| hybrid | 0.956 | 0.957 | 0.956 | 0.041 | 0.958 | 582869 | 26728 | 26383 | 631218 |

Precision is reported at the test partition's sampling ratio, which over-represents attacks relative to the 2.35% benign share of the full dataset. Recall and FPR are prevalence-independent.

## Confusion matrices (test partition)

| detector | actual \ pred | pred: Benign (0) | pred: Attack (1) |
|---|---|---|---|
| rules | Benign (0) | 634,226 (TN) | 23,720 (FP) |
| rules | Attack (1) | 27,156 (FN) | 582,096 (TP) |
| rules_strict | Benign (0) | 657,304 (TN) | 642 (FP) |
| rules_strict | Attack (1) | 437,502 (FN) | 171,750 (TP) |
| iforest | Benign (0) | 647,410 (TN) | 10,536 (FP) |
| iforest | Attack (1) | 340,981 (FN) | 268,271 (TP) |
| baseline | Benign (0) | 654,548 (TN) | 3,398 (FP) |
| baseline | Attack (1) | 80,749 (FN) | 528,503 (TP) |
| hybrid | Benign (0) | 631,218 (TN) | 26,728 (FP) |
| hybrid | Attack (1) | 26,383 (FN) | 582,869 (TP) |

## Recall per attack category (test partition)

| category | rows | rules | rules_strict | iforest | baseline | hybrid |
|---|---|---|---|---|---|---|
| Benign | 657946 | 0.036 | 0.001 | 0.016 | 0.005 | 0.041 |
| BruteForce | 2000 | 0.020 | 0.004 | 0.053 | 0.014 | 0.028 |
| DDoS | 352000 | 1.000 | 0.438 | 0.305 | 0.906 | 1.000 |
| DoS | 76000 | 1.000 | 0.228 | 0.242 | 0.733 | 1.000 |
| Mirai | 152000 | 0.999 | 0.001 | 0.920 | 0.998 | 1.000 |
| Recon | 10000 | 0.172 | 0.009 | 0.144 | 0.195 | 0.230 |
| Spoofing | 6000 | 0.067 | 0.006 | 0.073 | 0.005 | 0.070 |
| Web | 11252 | 0.007 | 0.001 | 0.076 | 0.008 | 0.014 |

## Alert triage (hybrid)

- Total alerts: 609,597 · high severity: 175,521 (28.8% of alerts)
- High-severity precision 0.996 · high-severity recall 0.287

## Reading the numbers

- Rules at one hit: recall 95.5% at 3.6% FPR. Flooding classes are textbook-visible; Recon, Web and BruteForce barely register because their per-row aggregates look benign.
- Rules at two hits: recall 28.2% at 0.1% FPR. Requiring two independent rules buys precision and costs the low-and-slow classes.
- Isolation Forest: recall 44.0% at 1.6% FPR, the weakest of the anomaly models here and the most sensitive to the benign capture it was fitted on.
- Deviation baseline: recall 86.7% at 0.5% FPR. The population-level version of the fingerprint idea is the strongest anomaly branch: it keeps DDoS/DoS far above the Isolation Forest at a fraction of the false positives.
- Hybrid: recall 95.7% at 4.1% FPR. The rules fast path is never suppressed, the deviation branch adds the quiet classes, and the confidence score plus top deviating features give the analyst a triage handle.

## Reproduction

```powershell
.venv\Scripts\python -m src.evaluation.benchmark
```

Dataset paths stay git-ignored; this report is versioned.
