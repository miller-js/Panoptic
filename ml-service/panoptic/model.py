"""Isolation Forest wrapper with percentile-calibrated scoring.

Why still Isolation Forest: it's fast, needs no labels, handles mixed
binary/continuous features, and its behaviour is explainable (path length in
random trees). The task here -- flag events unlike the learned baseline -- is
exactly what it's for. A deep model would add opacity and a training-data
appetite we don't have, for no measurable gain on ~30 tabular features.

What changed vs the original:

1. **StandardScaler in front.** Raw features span uid-sized integers to 0/1
   flags; scaling makes split thresholds comparable across features.
2. **Bigger ``max_samples`` and more trees** (config-driven). 256 samples
   under-fit a wide "normal" manifold and pushed almost every point to the same
   ``decision_function`` value.
3. **Percentile calibration.** ``decision_function`` for inliers clusters in a
   band a few hundredths wide. We store the sorted training scores once; at
   inference the raw score becomes its percentile in that distribution, so the
   ``anomaly_score`` actually uses the whole 0..1 range.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_NAMES


@dataclass
class Calibration:
    """Sorted training ``decision_function`` scores + summary stats."""

    sorted_scores: np.ndarray
    offset: float
    mean: float
    std: float

    def percentile_of(self, raw: float) -> float:
        """Fraction of training scores <= ``raw`` (0 = most anomalous)."""

        if self.sorted_scores.size == 0:
            return 0.5
        idx = np.searchsorted(self.sorted_scores, raw, side="right")
        return float(idx) / float(self.sorted_scores.size)

    def to_dict(self) -> dict:
        # Store a 1001-point quantile sketch rather than every score.
        qs = np.linspace(0.0, 1.0, 1001)
        quantiles = np.quantile(self.sorted_scores, qs) if self.sorted_scores.size else np.zeros_like(qs)
        return {
            "version": 1,
            "quantiles": quantiles.tolist(),
            "offset": self.offset,
            "mean": self.mean,
            "std": self.std,
            "n": int(self.sorted_scores.size),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Calibration":
        return cls(
            sorted_scores=np.asarray(data.get("quantiles", []), dtype=float),
            offset=float(data.get("offset", 0.0)),
            mean=float(data.get("mean", 0.0)),
            std=float(data.get("std", 1.0)) or 1.0,
        )

    @classmethod
    def fit(cls, raw_scores: np.ndarray, offset: float) -> "Calibration":
        scores = np.sort(np.asarray(raw_scores, dtype=float))
        return cls(
            sorted_scores=scores,
            offset=float(offset),
            mean=float(scores.mean()) if scores.size else 0.0,
            std=float(scores.std()) or 1.0,
        )


@dataclass
class Scored:
    anomaly_score: float   # 0..1, higher = more anomalous (percentile-based)
    raw_score: float       # raw decision_function output
    confidence: float      # 0..1, model's confidence the point is anomalous
    prediction: int        # legacy IsolationForest label: 1 normal / -1 anomaly


class AnomalyModel:
    def __init__(self, pipeline: Pipeline, calibration: Calibration, feature_names: list[str] | None = None):
        self.pipeline = pipeline
        self.calibration = calibration
        self.feature_names = feature_names or list(FEATURE_NAMES)

    # ---- training ---------------------------------------------------------

    @classmethod
    def train(cls, X: list[list[float]], model_kwargs: dict) -> "AnomalyModel":
        matrix = np.asarray(X, dtype=float)
        pipeline = Pipeline(
            steps=[
                ("scale", StandardScaler()),
                ("iforest", IsolationForest(**model_kwargs)),
            ]
        )
        pipeline.fit(matrix)
        raw = pipeline.decision_function(matrix)
        offset = getattr(pipeline.named_steps["iforest"], "offset_", 0.0)
        calibration = Calibration.fit(raw, offset)
        return cls(pipeline, calibration)

    # ---- inference ------------------------------------------------------

    def score(self, vector: list[float]) -> Scored:
        return self.score_many([vector])[0]

    def score_many(self, vectors: list[list[float]]) -> list[Scored]:
        matrix = np.asarray(vectors, dtype=float)
        raw = self.pipeline.decision_function(matrix)
        labels = self.pipeline.predict(matrix)
        out = []
        for raw_score, label in zip(raw, labels):
            pct = self.calibration.percentile_of(raw_score)
            anomaly_score = 1.0 - pct
            # Confidence: how far past the anomaly boundary this point sits.
            # sklearn defines that boundary at decision_function == 0 (predict
            # returns -1 below it), so measure the margin from 0 in units of the
            # training-score spread and squash to 0..1. Boundary -> ~0.5, deep
            # in the anomalous tail -> ~1, clearly-normal -> ~0.
            margin = -raw_score / self.calibration.std
            confidence = 1.0 / (1.0 + np.exp(-2.0 * margin))
            out.append(
                Scored(
                    anomaly_score=round(float(anomaly_score), 4),
                    raw_score=round(float(raw_score), 6),
                    confidence=round(float(confidence), 4),
                    prediction=int(label),
                )
            )
        return out

    # ---- persistence ----------------------------------------------------

    def save(self, model_path: str | Path, calibration_path: str | Path) -> None:
        joblib.dump({"pipeline": self.pipeline, "feature_names": self.feature_names}, model_path)
        Path(calibration_path).write_text(json.dumps(self.calibration.to_dict()))

    @classmethod
    def load(cls, model_path: str | Path, calibration_path: str | Path) -> "AnomalyModel":
        bundle = joblib.load(model_path)
        if isinstance(bundle, dict):
            pipeline = bundle["pipeline"]
            feature_names = bundle.get("feature_names")
        else:  # tolerate a bare estimator from an older artifact
            pipeline = bundle
            feature_names = None
        calibration = Calibration.from_dict(json.loads(Path(calibration_path).read_text()))
        return cls(pipeline, calibration, feature_names)
