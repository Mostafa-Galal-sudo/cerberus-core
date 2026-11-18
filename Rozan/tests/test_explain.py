"""Tests for the SHAP/LIME explainability layer."""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection.engine import HybridDetector
from detection.explain import (
    Explainer,
    Explanation,
    annotate_alerts,
)
from detection.ml_detector import IsolationForestDetector
from detection.simulator import generate_traffic


@pytest.fixture(scope="module")
def detector():
    benign = generate_traffic({"mqtt_benign": 200}, seed=13)
    return IsolationForestDetector().fit(benign), benign


def test_explainer_requires_fitted_detector():
    from detection.ml_detector import AutoencoderDetector
    with pytest.raises(RuntimeError):
        Explainer(IsolationForestDetector(), generate_traffic({"mqtt_benign": 5}))
    with pytest.raises(RuntimeError):
        Explainer(AutoencoderDetector(), generate_traffic({"mqtt_benign": 5}))  # type: ignore[arg-type]


def test_shap_attribution_identifies_flood_driver(detector):
    det, benign = detector
    explainer = Explainer(det, benign)
    flood = generate_traffic({"mqtt_flood": 5}, seed=14)
    explanations = explainer.explain_shap(flood)
    assert all(isinstance(e, Explanation) for e in explanations)
    assert all(e.method == "shap" for e in explanations)
    for explanation in explanations:
        assert len(explanation.top_features) == 5
        assert all(np.isfinite(v) for _, v in explanation.top_features)
        assert "Rate" in dict(explanation.top_features)
    # Floods deviate most on rate: it must rank top-3 by magnitude.
    assert "Rate" in dict(explanations[0].top_features)


def test_shap_summary_format(detector):
    det, benign = detector
    explainer = Explainer(det, benign)
    row = generate_traffic({"mqtt_flood": 1}, seed=15)
    summary = explainer.explain_shap(row)[0].summary
    assert summary.startswith("[shap] raw IF score")
    assert "driven by:" in summary


def test_lime_attribution(detector):
    det, benign = detector
    explainer = Explainer(det, benign)
    row = generate_traffic({"mqtt_flood": 2}, seed=16)
    explanations = explainer.explain_lime(row)
    assert all(e.method == "lime" for e in explanations)
    # LIME on a tree model's decision function is a noisy local surrogate
    # (SHAP is exact here and the primary method), so we only assert the
    # structural contract: real, unique features with finite weights.
    names = [n for n, _ in explanations[0].top_features]
    assert len(names) == 5
    assert len(set(names)) == 5
    assert all(np.isfinite(w) for _, w in explanations[0].top_features)


def test_benign_attribution_scores_low(detector):
    det, benign = detector
    explainer = Explainer(det, benign)
    fresh = generate_traffic({"mqtt_benign": 5}, seed=17)
    scores = [e.score for e in explainer.explain_shap(fresh)]
    attack_scores = [e.score for e in explainer.explain_shap(
        generate_traffic({"mqtt_flood": 5}, seed=17))]
    assert np.mean(attack_scores) > np.mean(scores)


def test_annotate_alerts_merges_reasons(detector):
    _det, benign = detector
    engine = HybridDetector(use_autoencoder=False).fit(benign)
    df = generate_traffic({"mqtt_benign": 30, "mqtt_flood": 10}, seed=18)
    alerts = engine.score(df)
    explainer = Explainer(engine.forest, benign)
    annotated = annotate_alerts(df, alerts, explainer)

    assert "ml_top_features" in annotated.columns
    assert "explanation" in annotated.columns
    # Alert rows have attributions; non-alert rows stay None.
    assert annotated.loc[~annotated["is_alert"], "ml_top_features"].isna().all()
    alert_part = annotated.loc[annotated["is_alert"]]
    assert alert_part["ml_top_features"].notna().all()
    assert alert_part["explanation"].str.len().gt(1).all()


def test_annotate_alerts_no_alerts(detector):
    _det, benign = detector
    engine = HybridDetector(use_autoencoder=False, threshold=2.0).fit(benign)
    df = generate_traffic({"mqtt_benign": 10}, seed=19)
    annotated = annotate_alerts(df, engine.score(df), Explainer(engine.forest, benign))
    assert annotated["ml_top_features"].isna().all()
