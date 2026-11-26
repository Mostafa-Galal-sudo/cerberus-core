import pandas as pd

from src.evaluation.benchmark import _confusion_table, partition
from src.evaluation.lab_check import run_lab_check


def test_lab_check_all_detectors_fire_on_anomalies(tmp_path):
    report = run_lab_check(seed=0, workdir=tmp_path)

    assert report["train_windows"] > 0
    assert report["normal_windows"] > 0
    assert report["normal_alert_rate"] <= 0.1
    assert report["normal_fp_alert_rate"] <= 0.1

    assert report["flood_windows"] > 0
    assert report["flood_rule_alerts"] == report["flood_windows"]
    assert report["flood_fp_alerts"] == report["flood_windows"]
    assert report["flood_hybrid_alerts"] == report["flood_windows"]

    assert report["bloat_windows"] > 0
    assert report["bloat_rule_alerts"] == report["bloat_windows"]
    assert report["bloat_fp_alerts"] == report["bloat_windows"]
    assert report["bloat_hybrid_alerts"] == report["bloat_windows"]

    assert report["rogue_windows"] > 0
    assert report["rogue_known"] is False
    assert report["rogue_hybrid_alerts"] == report["rogue_windows"]


def test_benchmark_confusion_table_and_partition():
    benign = pd.DataFrame({"source_file": ["a.csv", "b.csv", "c.csv", "d.csv"], "v": [1, 2, 3, 4]})
    attacks = pd.DataFrame({"source_file": ["x.csv"], "v": [9]})
    train, test = partition(benign, attacks, seed=0, test_share=0.5)
    assert len(train) == 2
    assert set(train["source_file"]).isdisjoint(set(test["source_file"]))
    md = _confusion_table({"hybrid": {"tn": 10, "fp": 1, "fn": 2, "tp": 20}})
    assert "(TN)" in md and "(FP)" in md and "(FN)" in md and "(TP)" in md
