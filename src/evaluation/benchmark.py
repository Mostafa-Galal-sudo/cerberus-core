from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from src.detection.dataset import class_files, drop_constant_features, load_sample
from src.detection.hybrid import HybridDetector
from src.detection.ml_model import AnomalyModel

THRESHOLD_QUANTILE = 0.995
IFOREST_CONTAMINATION = 0.005
DETECTORS = ("rules", "rules_strict", "iforest", "baseline", "hybrid")


def metrics(preds, truth):
    preds = np.asarray(preds).astype(int)
    truth = np.asarray(truth).astype(int)
    tp = int(((preds == 1) & (truth == 1)).sum())
    fp = int(((preds == 1) & (truth == 0)).sum())
    fn = int(((preds == 0) & (truth == 1)).sum())
    tn = int(((preds == 0) & (truth == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "fpr": fpr,
        "f1": f1, "accuracy": (tp + tn) / max(len(preds), 1),
    }


def partition(benign, attacks, seed=0, test_share=0.5):
    files = sorted(benign["source_file"].unique())
    shuffled = pd.Series(files).sample(frac=1.0, random_state=seed).tolist()
    cut = max(1, int(round(len(shuffled) * (1 - test_share))))
    if cut >= len(shuffled) and len(shuffled) > 1:
        cut = len(shuffled) - 1
    train_files = set(shuffled[:cut])
    test_files = set(shuffled[cut:])
    train = benign[benign["source_file"].isin(train_files)].reset_index(drop=True)
    test = pd.concat([
        benign[benign["source_file"].isin(test_files)],
        attacks,
    ], ignore_index=True)
    return train, test


def load_frames(root, benign_rows=None, attack_rows=2000, seed=0):
    benign = load_sample(root, rows_per_file=benign_rows, categories={"Benign"}, seed=seed)
    attacks = load_sample(
        root,
        rows_per_file=attack_rows,
        categories={"DDoS", "DoS", "Mirai", "Recon", "Web", "BruteForce", "Spoofing"},
        seed=seed,
    )
    combined = drop_constant_features(pd.concat([benign, attacks], ignore_index=True))
    benign_mask = combined["category"] == "Benign"
    return combined[benign_mask].reset_index(drop=True), combined[~benign_mask].reset_index(drop=True)


def per_category(detections, truth_frame):
    frame = truth_frame[["category", "is_attack"]].copy()
    for name in DETECTORS:
        frame[name] = np.asarray(detections[name]).astype(int)
    rates = frame.groupby("category")[list(DETECTORS)].mean()
    counts = frame.groupby("category")["is_attack"].size().rename("rows")
    return rates.join(counts)[["rows", *DETECTORS]].reset_index()


def triage_summary(hybrid_output, truth):
    alert = hybrid_output["alert"].to_numpy().astype(bool)
    high = (hybrid_output["severity"] == "high").to_numpy()
    truth = np.asarray(truth).astype(int)
    high_alerts = alert & high
    tp_high = int((high_alerts & (truth == 1)).sum())
    fp_high = int((high_alerts & (truth == 0)).sum())
    return {
        "total_alerts": int(alert.sum()),
        "high_alerts": int(high_alerts.sum()),
        "high_share": float(high_alerts.sum() / max(alert.sum(), 1)),
        "high_precision": float(tp_high / max(tp_high + fp_high, 1)),
        "high_recall": float(tp_high / max(truth.sum(), 1)),
    }


def evaluate(root, seed=0, benign_rows=None, attack_rows=2000):
    benign, attacks = load_frames(root, benign_rows=benign_rows, attack_rows=attack_rows, seed=seed)
    train, test = partition(benign, attacks, seed=seed)

    hybrid = HybridDetector(quantile=THRESHOLD_QUANTILE)
    hybrid.fit(train)
    iforest = AnomalyModel(
        contamination=IFOREST_CONTAMINATION,
        n_estimators=300,
        max_features=0.5,
    ).fit(train)

    truth = test["is_attack"].to_numpy()
    rule_preds, _, _ = hybrid.rules.predict(test, min_hits=1)
    strict_preds, _, _ = hybrid.rules.predict(test, min_hits=2)
    if_preds, _ = iforest.predict(test)
    base_preds, _ = hybrid.baseline.predict(test)
    hybrid_output = hybrid.predict(test)

    detections = {
        "rules": rule_preds,
        "rules_strict": strict_preds,
        "iforest": if_preds,
        "baseline": base_preds,
        "hybrid": hybrid_output["alert"].to_numpy(),
    }
    summary = pd.DataFrame([{"detector": name, **metrics(detections[name], truth)} for name in DETECTORS])
    confusion_matrices = {
        row["detector"]: {
            "tn": int(row["tn"]),
            "fp": int(row["fp"]),
            "fn": int(row["fn"]),
            "tp": int(row["tp"]),
        }
        for _, row in summary.iterrows()
    }

    return {
        "summary": summary,
        "confusion_matrices": confusion_matrices,
        "per_category": per_category(detections, test),
        "triage": triage_summary(hybrid_output, truth),
        "composition": {
            "train_rows": len(train),
            "train_files": int(train["source_file"].nunique()),
            "test_rows": len(test),
            "test_files": int(test["source_file"].nunique()),
            "test_benign_rows": int((truth == 0).sum()),
            "test_attack_rows": int(truth.sum()),
            "attack_categories": int(test.loc[test["is_attack"] == 1, "category"].nunique()),
            "features": len(hybrid.baseline.columns_),
            "iforest_limit": float(iforest.limit_),
            "baseline_limit": float(hybrid.baseline.limit_),
        },
    }


def _table(frame, columns, floatfmt="{:.3f}"):
    head = "| " + " | ".join(columns) + " |"
    sep = "|" + "|".join(["---"] * len(columns)) + "|"
    rows = []
    for _, row in frame.iterrows():
        cells = []
        for column in columns:
            value = row[column]
            cells.append(floatfmt.format(value) if isinstance(value, (float, np.floating)) else str(value))
        rows.append("| " + " | ".join(cells) + " |")
    return "\n".join([head, sep, *rows])


def _confusion_table(confusion_matrices):
    lines = [
        "| detector | actual \\ pred | pred: Benign (0) | pred: Attack (1) |",
        "|---|---|---|---|",
    ]
    for name, cm in confusion_matrices.items():
        lines.append(f"| {name} | Benign (0) | {cm['tn']:,} (TN) | {cm['fp']:,} (FP) |")
        lines.append(f"| {name} | Attack (1) | {cm['fn']:,} (FN) | {cm['tp']:,} (TP) |")
    return "\n".join(lines)


def _verdict_section(results):
    summary = results["summary"].set_index("detector")
    per_cat = results["per_category"]
    lines = [
        "---",
        "",
        "## Model Comparison & Verdict",
        "",
        "### Head-to-head scorecard",
        "",
        "| Metric | Best | Runner-up | Third | Worst |",
        "|---|---|---|---|---|",
    ]
    for metric, ascending in (
        ("f1", False),
        ("recall", False),
        ("precision", False),
        ("fpr", True),
        ("accuracy", False),
    ):
        ordered = summary[metric].sort_values(ascending=ascending)
        picks = (0, 1, 2, len(ordered) - 1)
        cells = [
            f"`{ordered.index[i]}` {float(ordered.iloc[i]):.3f}" for i in picks
        ]
        lines.append(f"| {metric} | " + " | ".join(cells) + " |")

    lines += [
        "",
        "### Best recall per attack category",
        "",
        "| Category | Best detector | Recall |",
        "|---|---|---|",
    ]
    for _, row in per_cat.iterrows():
        category = str(row["category"])
        if category.lower().startswith("benign"):
            # Benign "recall" is the false-positive rate, not an attack detection rate.
            continue
        scores = {name: float(row[name]) for name in DETECTORS}
        best = max(scores, key=scores.get)
        lines.append(f"| {category} | `{best}` | {scores[best]:.3f} |")

    lines += [
        "",
        "### Reading the comparison",
        "",
        f"- Highest F1: `{summary['f1'].idxmax()}` ({summary['f1'].max():.3f}); highest recall: `{summary['recall'].idxmax()}` ({summary['recall'].max():.3f}).",
        f"- Lowest FPR: `{summary['fpr'].idxmin()}` ({summary['fpr'].min():.3f}); lowest recall: `{summary['recall'].idxmin()}` ({summary['recall'].min():.3f}).",
        "- `hybrid` is the recommended primary detector when recall and explainability matter; its union of rules and deviation raises FPR.",
        "- `rules_strict` is an escalation tier only: best precision and lowest FPR, but very low recall.",
        "- `iforest` and `baseline` are unsupervised cross-checks; neither sees the application-layer low-and-slow patterns exposed by these features.",
        "",
        "This section is generated by `render()` from the same results as the tables above.",
        "",
    ]
    return lines


def render(results, root, file_count):
    composition = results["composition"]
    summary = results["summary"].set_index("detector")
    per_cat = results["per_category"]
    triage = results["triage"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rules = summary.loc["rules"]
    strict = summary.loc["rules_strict"]
    iforest = summary.loc["iforest"]
    baseline = summary.loc["baseline"]
    hybrid = summary.loc["hybrid"]

    lines = [
        "# CICIoT2023 benchmark — detection engine v1",
        "",
        f"Generated {now} · dataset `{root}` ({file_count} capture files) · seed 0",
        "",
        "## Protocol",
        "",
        "- One feature pipeline for every detector: the 39 numeric CICIoT2023 features, constant columns dropped once over the sampled data.",
        "- Training uses benign traffic only. No attack row is ever shown to any detector during fitting.",
        f"- Alarm thresholds are fixed a priori from the benign training distribution ({THRESHOLD_QUANTILE:.1%} quantile for the deviation baseline, contamination {IFOREST_CONTAMINATION:.1%} for the Isolation Forest). Nothing is tuned on the test partition.",
        "- Benign captures are split at file level: whole capture files go to training or to testing, so no capture contributes rows to both sides.",
        "- The per-device behavioural fingerprint is not applied here: CICIoT2023 rows carry no device identity. It is validated on the lab MQTT data instead (C2-T09).",
        "",
        "## Partitions",
        "",
        "| split | rows | contents |",
        "|---|---|---|",
        f"| train | {composition['train_rows']:,} | {composition['train_files']} benign capture files |",
        f"| test | {composition['test_rows']:,} | {composition['test_benign_rows']:,} benign rows + {composition['test_attack_rows']:,} attack rows across {composition['attack_categories']} categories, {composition['test_files']} files |",
        "",
        f"Feature columns: {composition['features']} · baseline limit {composition['baseline_limit']:.3f} · Isolation Forest limit {composition['iforest_limit']:.3f}",
        "",
        "## Headline metrics (test partition)",
        "",
        _table(results["summary"], ["detector", "precision", "recall", "f1", "fpr", "accuracy", "tp", "fp", "fn", "tn"]),
        "",
        "Precision is reported at the test partition's sampling ratio, which over-represents attacks relative to the 2.35% benign share of the full dataset. Recall and FPR are prevalence-independent.",
        "",
        "## Confusion matrices (test partition)",
        "",
        _confusion_table(results["confusion_matrices"]),
        "",
        "## Recall per attack category (test partition)",
        "",
        _table(per_cat, ["category", "rows", "rules", "rules_strict", "iforest", "baseline", "hybrid"]),
        "",
        "## Alert triage (hybrid)",
        "",
        f"- Total alerts: {triage['total_alerts']:,} · high severity: {triage['high_alerts']:,} ({triage['high_share']:.1%} of alerts)",
        f"- High-severity precision {triage['high_precision']:.3f} · high-severity recall {triage['high_recall']:.3f}",
        "",
        "## Reading the numbers",
        "",
        f"- Rules at one hit: recall {rules['recall']:.1%} at {rules['fpr']:.1%} FPR. Flooding classes are textbook-visible; Recon, Web and BruteForce barely register because their per-row aggregates look benign.",
        f"- Rules at two hits: recall {strict['recall']:.1%} at {strict['fpr']:.1%} FPR. Requiring two independent rules buys precision and costs the low-and-slow classes.",
        f"- Isolation Forest: recall {iforest['recall']:.1%} at {iforest['fpr']:.1%} FPR, the weakest of the anomaly models here and the most sensitive to the benign capture it was fitted on.",
        f"- Deviation baseline: recall {baseline['recall']:.1%} at {baseline['fpr']:.1%} FPR. The population-level version of the fingerprint idea is the strongest anomaly branch: it keeps DDoS/DoS far above the Isolation Forest at a fraction of the false positives.",
        f"- Hybrid: recall {hybrid['recall']:.1%} at {hybrid['fpr']:.1%} FPR. The rules fast path is never suppressed, the deviation branch adds the quiet classes, and the confidence score plus top deviating features give the analyst a triage handle.",
        "",
        "## Reproduction",
        "",
        "```powershell",
        ".venv\\Scripts\\python -m src.evaluation.benchmark",
        "```",
        "",
        *_verdict_section(results),
        "Dataset paths stay git-ignored; this report is versioned.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    dataset_root = Path("data/raw/ciciot2023/CSV")
    results = evaluate(dataset_root, seed=0)
    entries = class_files(dataset_root)
    output = Path("results/benchmark_ciciot_v1.md")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render(results, dataset_root, len(entries)), encoding="utf-8")
    print(results["summary"][["detector", "precision", "recall", "f1", "fpr"]].to_string(index=False))
    print(results["per_category"].to_string(index=False))
    print("triage:", results["triage"])
    print(f"written: {output}")
