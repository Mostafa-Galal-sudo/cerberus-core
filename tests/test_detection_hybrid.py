import numpy as np
import pandas as pd

from src.detection.baseline import DeviationBaseline
from src.detection.features import FEATURE_NAMES
from src.detection.fingerprint import DeviceFingerprint
from src.detection.hybrid import HybridDetector
from src.detection.rules_engine import RULES

COLUMNS = [col for _, col, _ in RULES]


def benign_frame(n=400, jitter=0.02, seed=0):
    rng = np.random.default_rng(seed)
    base = {
        "Rate": 400.0,
        "IAT": 0.002,
        "syn_flag_number": 0.0,
        "ack_flag_number": 0.6,
        "ICMP": 0.0,
        "Number": 10.0,
        "Header_Length": 22.0,
        "Std": 170.0,
    }
    data = {col: np.abs(np.full(n, value) + rng.normal(0, jitter * abs(value) + 1e-3, n)) for col, value in base.items()}
    return pd.DataFrame(data)


def attack_frame(n=5):
    return pd.DataFrame({col: np.full(n, value, dtype=float) for col, value in {
        "Rate": 25_000.0,
        "IAT": 0.00001,
        "syn_flag_number": 1.0,
        "ack_flag_number": 0.0,
        "ICMP": 0.0,
        "Number": 500.0,
        "Header_Length": 60.0,
        "Std": 4000.0,
    }.items()})


def test_baseline_flags_out_of_distribution_rows():
    baseline = DeviationBaseline(quantile=0.99).fit(benign_frame())
    preds, scores = baseline.predict(attack_frame())
    assert preds.sum() == 5
    assert scores.min() > baseline.limit_


def test_baseline_stays_quiet_on_benign_like_rows():
    baseline = DeviationBaseline(quantile=0.99).fit(benign_frame())
    preds, _ = baseline.predict(benign_frame(n=200, jitter=0.02, seed=7))
    assert preds.mean() <= 0.05


def test_baseline_drivers_name_the_shifted_features():
    baseline = DeviationBaseline(quantile=0.99).fit(benign_frame())
    drivers = baseline.drivers(attack_frame(1))
    names = [name for name, _ in drivers[0]]
    assert "Rate" in names
    assert all(name in COLUMNS for name in names)


def test_baseline_limit_is_positive_and_finite():
    baseline = DeviationBaseline(quantile=0.99).fit(benign_frame())
    assert np.isfinite(baseline.limit_)
    assert baseline.limit_ > 1.0


def test_hybrid_alerts_on_rules_and_on_deviation_alone():
    detector = HybridDetector(quantile=0.99).fit(benign_frame())
    output = detector.predict(attack_frame())
    assert output["alert"].sum() == len(output)
    assert (output["rule_hits"] >= 1).all()
    assert (output["severity"] == "high").all()


def test_hybrid_keeps_benign_quiet():
    detector = HybridDetector(quantile=0.99).fit(benign_frame())
    output = detector.predict(benign_frame(n=200, jitter=0.02, seed=11))
    assert output["alert"].mean() <= 0.05


def test_hybrid_confidence_is_bounded_and_explained():
    detector = HybridDetector(quantile=0.99).fit(benign_frame())
    output = detector.predict(attack_frame())
    assert output["confidence"].between(0.0, 1.0).all()
    assert output["explanation"].str.contains("confidence:").all()


def test_hybrid_fingerprint_signal_can_raise_an_alert():
    detector = HybridDetector(quantile=0.99).fit(benign_frame())
    quiet = benign_frame(n=2, jitter=0.0, seed=3)
    fp_scores = np.array([0.0, 12.0])
    output = detector.predict(quiet, fp_scores=fp_scores, fp_limit=4.0)
    assert output["alert"].tolist() == [0, 1]


def _fp_row(device_id, rate=0.1, payload=180.0):
    row = {name: 0.0 for name in FEATURE_NAMES}
    row.update({
        "device_id": device_id,
        "window_start": 0.0,
        "event_count": 6.0,
        "rate_per_sec": rate,
        "payload_mean": payload,
        "payload_max": payload,
        "payload_min": payload,
        "gap_mean": 10.0,
        "publish_share": 1.0,
    })
    return row


def test_fingerprint_min_windows_fallback_and_known():
    rows = [_fp_row("dev_a") for _ in range(6)] + [_fp_row("dev_b") for _ in range(2)]
    fp = DeviceFingerprint(min_windows=5).fit(rows)
    assert fp.known("dev_a") is True
    assert fp.known("dev_b") is False
    assert fp.known("unseen") is False
    preds, scores, _ = fp.predict([_fp_row("dev_a"), _fp_row("dev_b"), _fp_row("unseen", rate=5.0)])
    assert len(preds) == 3
    assert scores[2] > scores[0]


def test_hybrid_flags_unknown_device_with_explanation():
    fp = DeviceFingerprint(min_windows=3).fit([_fp_row("dev_a") for _ in range(4)])
    detector = HybridDetector(quantile=0.99, fingerprint=fp).fit(benign_frame())
    quiet = benign_frame(n=2, jitter=0.0, seed=3)
    quiet["device_id"] = ["dev_a", "dev_unknown"]
    output = detector.predict(quiet, fp_scores=np.array([0.0, 0.0]), fp_limit=10.0)
    assert output["alert"].tolist() == [0, 1]
    assert output.loc[1, "severity"] == "high"
    assert "unknown_device:dev_unknown" in output.loc[1, "explanation"]
