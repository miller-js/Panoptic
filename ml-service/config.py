"""Central configuration for the Panoptic ML service.

Everything that a deployment might reasonably want to tune is read from an
environment variable here, with a sane default. Nothing security-relevant
(risk weights, thresholds, model params) is hardcoded deep in the code -- it
all flows from this module or the JSON files under ``artifacts/``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

ARTIFACTS_DIR = Path(os.environ.get("PANOPTIC_ARTIFACTS_DIR", Path(__file__).parent / "artifacts"))

MODEL_PATH = ARTIFACTS_DIR / "model.pkl"
PROFILE_PATH = ARTIFACTS_DIR / "profile.json"
CALIBRATION_PATH = ARTIFACTS_DIR / "calibration.json"
RISK_WEIGHTS_PATH = ARTIFACTS_DIR / "risk_weights.json"

# Detection/schema versions. Bump MODEL_VERSION when the feature vector or model
# changes; DETECTION_VERSION when risk/mitre/explanation logic changes. Both are
# written onto every alert so a stored alert can always be traced back to the
# logic that produced it.
MODEL_VERSION = "2.0"
DETECTION_VERSION = "2.0"

ALERTS_INDEX = os.environ.get("PANOPTIC_ALERTS_INDEX", "panoptic-alerts")
STATE_INDEX = os.environ.get("PANOPTIC_STATE_INDEX", "panoptic-state")
SOURCE_INDEX = os.environ.get("PANOPTIC_SOURCE_INDEX", "filebeat-*")


def _get_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass
class ElasticConfig:
    addr: str = os.environ.get("PANOPTIC_ES_ADDR", "http://192.168.10.100:9200")
    user: str = os.environ.get("PANOPTIC_ES_USER", "elastic")
    password: str = os.environ.get("PANOPTIC_ES_PASSWORD", "changeme")
    request_timeout: int = _get_int("PANOPTIC_ES_TIMEOUT", 30)


@dataclass
class ModelConfig:
    """IsolationForest hyper-parameters.

    Defaults are chosen for this dataset (~320k mostly-homogeneous Linux auditd
    events): more trees and a much larger ``max_samples`` than sklearn's default
    of 256, because the "normal" manifold here is wide and 256 samples badly
    under-describes it (a big contributor to every event scoring ~35).
    """

    n_estimators: int = _get_int("PANOPTIC_IF_N_ESTIMATORS", 300)
    max_samples: int = _get_int("PANOPTIC_IF_MAX_SAMPLES", 4096)
    # "auto" lets the training data decide the inlier/outlier boundary. A float
    # in (0, 0.5] pins it. Only affects the binary predict() label, not the
    # continuous decision_function used for risk scoring.
    contamination: str = os.environ.get("PANOPTIC_IF_CONTAMINATION", "auto")
    max_features: float = _get_float("PANOPTIC_IF_MAX_FEATURES", 1.0)
    random_state: int = _get_int("PANOPTIC_IF_RANDOM_STATE", 42)

    def sklearn_kwargs(self) -> dict:
        contamination: object = self.contamination
        if contamination != "auto":
            try:
                contamination = float(contamination)
            except (TypeError, ValueError):
                contamination = "auto"
        return {
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "contamination": contamination,
            "max_features": self.max_features,
            "random_state": self.random_state,
            "n_jobs": -1,
        }


@dataclass
class TrainConfig:
    sample_size: int = _get_int("PANOPTIC_TRAIN_SAMPLE_SIZE", 80000)
    # The profile is built from a much larger sweep than the model fit: rarity
    # features that only saw a small slice of the corpus at train time would
    # read as "novel" for most live events purely because of the sampling.
    profile_sample_size: int = _get_int("PANOPTIC_PROFILE_SAMPLE_SIZE", 300000)
    # Random seed for the Elasticsearch random_score sampler -- pin it so a
    # retrain on the same data is reproducible.
    sample_seed: int = _get_int("PANOPTIC_TRAIN_SAMPLE_SEED", 1337)


@dataclass
class ScoringConfig:
    batch_size: int = _get_int("PANOPTIC_BATCH_SIZE", 1000)
    loop_interval_seconds: int = _get_int("PANOPTIC_LOOP_INTERVAL", 300)
    # Audit record types that are sub-records of a SYSCALL event and carry no
    # standalone security meaning. They are consumed (cursor advances past them)
    # and used to enrich the parent SYSCALL, but never scored on their own.
    child_record_types: tuple = (
        "PATH",
        "CWD",
        "PROCTITLE",
        "EXECVE",
        "SOCKADDR",
    )


@dataclass
class SeverityBands:
    """Lower bound (inclusive) of each severity band on the 0-100 scale."""

    informational: int = 0
    low: int = _get_int("PANOPTIC_SEV_LOW", 20)
    medium: int = _get_int("PANOPTIC_SEV_MEDIUM", 40)
    high: int = _get_int("PANOPTIC_SEV_HIGH", 60)
    critical: int = _get_int("PANOPTIC_SEV_CRITICAL", 80)

    def classify(self, score: float) -> str:
        if score >= self.critical:
            return "critical"
        if score >= self.high:
            return "high"
        if score >= self.medium:
            return "medium"
        if score >= self.low:
            return "low"
        return "informational"


@dataclass
class Config:
    elastic: ElasticConfig = field(default_factory=ElasticConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    train: TrainConfig = field(default_factory=TrainConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    severity: SeverityBands = field(default_factory=SeverityBands)

    def as_dict(self) -> dict:
        return asdict(self)


def load_config() -> Config:
    return Config()


# --- Risk factor weights ------------------------------------------------------
#
# These drive the composite risk score (see panoptic/risk.py). They live in a
# JSON file so they can be tuned without a code change or rebuild, but ship with
# defensible defaults documented in the README.

DEFAULT_RISK_WEIGHTS = {
    "impact": {
        "privilege": 0.40,
        "confidentiality": 0.25,
        "integrity": 0.25,
        "availability": 0.10,
    },
    "exploitability": {
        "privilege_required": 0.30,
        "attack_complexity": 0.25,
        "auth_context": 0.20,
        "remote": 0.25,
    },
    # How the technical severity (impact + exploitability) is combined.
    # Impact-weighted, matching CVSS's general lean toward consequence.
    "technical_severity": {"impact": 0.6, "exploitability": 0.4},
    # A confidently-mapped ATT&CK technique raises the technical severity floor
    # to base + scale * technique_severity (capped at 1.0). Keeps known-bad
    # behaviour from scoring low just because its raw impact math is modest.
    "technique_floor": {"base": 0.35, "scale": 0.6},
    # The context modifier scales technical severity up or down based on how
    # anomalous / rare / attributable the behaviour is. Clamped to [min, max].
    "context_modifier": {
        "base": 0.45,
        "anomaly": 0.35,
        "rarity": 0.15,
        "technique": 0.15,
        "asset": 0.20,
        "min": 0.25,
        "max": 1.30,
    },
}


def load_risk_weights() -> dict:
    if RISK_WEIGHTS_PATH.exists():
        try:
            loaded = json.loads(RISK_WEIGHTS_PATH.read_text())
            return _merge(DEFAULT_RISK_WEIGHTS, loaded)
        except (json.JSONDecodeError, OSError):
            pass
    return json.loads(json.dumps(DEFAULT_RISK_WEIGHTS))


def _merge(base: dict, override: dict) -> dict:
    out = json.loads(json.dumps(base))
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


# --- Per-host asset criticality --------------------------------------------
#
# 0.0 = throwaway, 0.5 = standard, 1.0 = crown jewel. Unknown hosts default to
# 0.5. Override with PANOPTIC_ASSET_CRITICALITY='{"db-prod-1": 0.9}'.

def load_asset_criticality() -> dict:
    raw = os.environ.get("PANOPTIC_ASSET_CRITICALITY", "")
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return {str(k): float(v) for k, v in parsed.items()}
    except (json.JSONDecodeError, ValueError, AttributeError):
        return {}


DEFAULT_ASSET_CRITICALITY = 0.5
