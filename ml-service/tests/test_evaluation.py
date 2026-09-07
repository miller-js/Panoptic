"""End-to-end: train on synthetic 'normal', evaluate against labelled attacks.

This is the CI-able sanity gate for the detection pipeline. It does NOT assert
production-grade metrics (the synthetic baseline is tiny and clean); it asserts
that the pipeline meaningfully separates the two classes and that scores are
not collapsed.
"""

import config as cfg
from evaluate import SEVERITY_RANK, evaluate
from panoptic import scenarios
from panoptic.context import build_context
from panoptic.detector import Detector
from panoptic.enrich import build_enrichment_map
from panoptic.features import feature_vector
from panoptic.model import AnomalyModel
from panoptic.profile import Profile
from panoptic.risk import RiskEngine
from panoptic.signals import RollingSignals


def _build_detector(repeats: int = 4) -> Detector:
    config = cfg.load_config()
    child = set(config.scoring.child_record_types)
    events = scenarios.generate(repeats=repeats)
    normal_logs = [log for log, lab in events if lab["label"] == "normal"]

    enrichment = build_enrichment_map(normal_logs)
    rolling = RollingSignals()
    contexts = []
    for log in normal_logs:
        ctx = build_context(log, None)
        sig = rolling.update(ctx)
        if ctx.record_type in child:
            continue
        if ctx.event_id and ctx.event_id in enrichment:
            ctx = build_context(log, enrichment[ctx.event_id])
            ctx.recent_auth_failures = sig["recent_auth_failures"]
        contexts.append(ctx)

    profile = Profile.from_events(contexts)
    X = [feature_vector(c, profile) for c in contexts]
    # duplicate to give IsolationForest enough rows
    X = X * 5
    model = AnomalyModel.train(X, {"n_estimators": 120, "max_samples": min(256, len(X)),
                                   "contamination": "auto", "random_state": 0, "n_jobs": 1})
    engine = RiskEngine(cfg.load_risk_weights(), config.severity)
    return Detector(model, profile, engine, model_version="test", detection_version="test",
                    child_record_types=config.scoring.child_record_types)


def test_pipeline_separates_malicious_from_normal():
    detector = _build_detector()
    events = scenarios.generate(repeats=3)
    result = evaluate(detector, events, SEVERITY_RANK["medium"])

    normal = result["risk_score_distribution"]["normal"]
    malicious = result["risk_score_distribution"]["malicious"]
    assert malicious["mean"] > normal["mean"] + 10

    # recall: most attack scenarios raise at least one alert
    assert result["metrics"]["recall"] >= 0.6
    # false positive rate on the (clean) normal set should be modest
    assert result["metrics"]["false_positive_rate"] <= 0.35


def test_scores_are_not_collapsed():
    detector = _build_detector()
    events = scenarios.generate(repeats=3)
    result = evaluate(detector, events, SEVERITY_RANK["high"])
    distinct = {row["risk_score"] for row in result["rows"]}
    assert len(distinct) >= 6


def test_bruteforce_and_priv_esc_detected():
    detector = _build_detector()
    events = scenarios.generate(repeats=2)
    result = evaluate(detector, events, SEVERITY_RANK["medium"])
    rates = result["detection_rate_by_scenario"]
    assert rates["ssh_bruteforce"]["rate"] > 0
    assert rates["priv_esc_root_shell"]["rate"] > 0


def test_mitre_mapping_accuracy_reasonable():
    detector = _build_detector()
    events = scenarios.generate(repeats=2)
    result = evaluate(detector, events, SEVERITY_RANK["high"])
    assert result["mitre"]["accuracy"] is not None
    assert result["mitre"]["accuracy"] >= 0.6
