import numpy as np

from panoptic.model import AnomalyModel, Calibration


def test_calibration_percentile_monotonic():
    cal = Calibration.fit(np.linspace(-1, 1, 1001), offset=0.0)
    assert cal.percentile_of(-1.0) < cal.percentile_of(0.0) < cal.percentile_of(1.0)


def test_anomaly_score_spreads_across_range(trained_model):
    rng = np.random.default_rng(1)
    n = len(trained_model.feature_names)
    vectors = np.abs(rng.normal(0, 0.4, size=(300, n)))
    vectors[:5] += 6.0  # a few blatant outliers
    scores = [trained_model.score(v.tolist()).anomaly_score for v in vectors]
    # the distribution should not be a single spike
    assert len(set(round(s, 2) for s in scores)) > 20
    assert max(scores) > 0.9
    assert min(scores) < 0.5


def test_outlier_scores_higher_than_inlier(trained_model):
    n = len(trained_model.feature_names)
    inlier = [0.3] * n
    inlier[0] = 12.0  # hour: within the trained 8-18 range
    outlier = [9.0] * n
    outlier[0] = 12.0
    inlier_s = trained_model.score(inlier)
    outlier_s = trained_model.score(outlier)
    assert outlier_s.anomaly_score > inlier_s.anomaly_score
    assert outlier_s.confidence >= inlier_s.confidence


def test_save_load_roundtrip(trained_model, tmp_path):
    mp, cp = tmp_path / "m.pkl", tmp_path / "c.json"
    trained_model.save(mp, cp)
    reloaded = AnomalyModel.load(mp, cp)
    v = [0.5] * len(trained_model.feature_names)
    # calibration is persisted as a 1001-point quantile sketch, so allow a
    # small approximation error vs the in-memory full score array
    assert abs(reloaded.score(v).anomaly_score - trained_model.score(v).anomaly_score) < 0.02
    assert reloaded.score(v).raw_score == trained_model.score(v).raw_score
    assert reloaded.feature_names == trained_model.feature_names


def test_prediction_label_follows_calibrated_percentile(trained_model):
    n = len(trained_model.feature_names)
    trained_model.anomaly_label_pct = 0.95
    normal = trained_model.score([0.3] * n)
    extreme = trained_model.score([12.0] * n)
    assert extreme.prediction == -1
    assert normal.prediction == 1
    assert (extreme.anomaly_score >= 0.95) == (extreme.prediction == -1)


def test_score_many_matches_score(trained_model):
    n = len(trained_model.feature_names)
    vs = [[0.2] * n, [5.0] * n]
    many = trained_model.score_many(vs)
    assert [m.anomaly_score for m in many] == [trained_model.score(v).anomaly_score for v in vs]
