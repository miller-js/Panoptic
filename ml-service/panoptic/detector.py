"""Orchestrator: raw log batch -> alert documents.

Wires the stages together (context -> features -> model -> mitre -> risk ->
explain -> alert) and owns the loaded model + profile. Deliberately has no
Elasticsearch knowledge -- ``elastic.py`` feeds it dicts and stores what it
returns, so the whole pipeline is unit-testable with plain dicts.
"""

from __future__ import annotations

from dataclasses import dataclass

from .alerts import alert_id, build_alert
from .context import EventContext, build_context
from .enrich import build_enrichment_map
from .explain import build_explanation
from .features import FEATURE_NAMES, extract_features, feature_vector
from .mitre import map_techniques
from .model import AnomalyModel, Scored
from .profile import Profile
from .risk import RiskEngine
from .signals import RollingSignals


@dataclass
class Detection:
    context: EventContext
    scored: Scored
    features: dict
    techniques: list
    risk: object
    explanation: dict
    signals: dict

    def to_alert(self, model_version: str, detection_version: str) -> dict:
        return build_alert(
            self.context,
            self.scored,
            self.risk,
            self.techniques,
            self.explanation,
            model_version=model_version,
            detection_version=detection_version,
            signals=self.signals,
        )

    def alert_id(self) -> str:
        return alert_id(self.context)


class Detector:
    def __init__(
        self,
        model: AnomalyModel,
        profile: Profile,
        risk_engine: RiskEngine,
        *,
        model_version: str,
        detection_version: str,
        child_record_types: tuple = (),
        asset_criticality: dict | None = None,
        default_criticality: float = 0.5,
    ):
        self.model = model
        self.profile = profile
        self.risk_engine = risk_engine
        self.model_version = model_version
        self.detection_version = detection_version
        self.child_record_types = set(child_record_types)
        self.asset_criticality = asset_criticality or {}
        self.default_criticality = default_criticality

    # ---- helpers --------------------------------------------------------

    def _criticality(self, host: str | None) -> float:
        if host and host in self.asset_criticality:
            return self.asset_criticality[host]
        return self.default_criticality

    def is_scorable(self, record_type: str) -> bool:
        return record_type.upper() not in self.child_record_types

    # ---- single event (used by tests + evaluation) ---------------------

    def detect(self, ctx: EventContext, signals: dict | None = None) -> Detection:
        signals = signals or {"recent_auth_failures": ctx.recent_auth_failures,
                              "recent_distinct_ports": ctx.recent_distinct_ports}
        feats = extract_features(ctx, self.profile, signals)
        scored = self.model.score(feature_vector(ctx, self.profile, signals))
        return self._assemble(ctx, feats, scored, signals)

    def _assemble(self, ctx, feats, scored: Scored, signals: dict) -> Detection:
        techniques = map_techniques(ctx, signals)
        risk = self.risk_engine.evaluate(ctx, feats, scored.anomaly_score, techniques)
        explanation = build_explanation(ctx, risk, scored.anomaly_score, scored.confidence, techniques)
        return Detection(ctx, scored, feats, techniques, risk, explanation, signals)

    def detect_log(self, log: dict, enrichment: dict | None = None, signals: dict | None = None) -> Detection:
        ctx = build_context(log, enrichment, self._criticality((log.get("host") or {}).get("hostname")))
        return self.detect(ctx, signals)

    # ---- batch (used by the scoring loop) -----------------------------

    def score_batch(self, logs: list[dict]) -> list[Detection]:
        enrichment = build_enrichment_map(logs)
        rolling = RollingSignals()

        prepared: list[tuple] = []  # (ctx, features, signals)
        for log in logs:
            host = (log.get("host") or {}).get("hostname") or (log.get("host") or {}).get("name")
            ctx = build_context(log, None, self._criticality(host))
            # feed EVERY event (children included) so windowed counts are right
            signals = rolling.update(ctx)
            if not self.is_scorable(ctx.record_type):
                continue
            if ctx.event_id and ctx.event_id in enrichment:
                ctx = build_context(log, enrichment[ctx.event_id], self._criticality(host))
                ctx.recent_auth_failures = signals["recent_auth_failures"]
                ctx.recent_distinct_ports = signals["recent_distinct_ports"]
            feats = extract_features(ctx, self.profile, signals)
            prepared.append((ctx, feats, signals))

        if not prepared:
            return []

        vectors = [[f[name] for name in FEATURE_NAMES] for _, f, _ in prepared]
        scores = self.model.score_many(vectors)
        return [
            self._assemble(ctx, feats, scored, signals)
            for (ctx, feats, signals), scored in zip(prepared, scores)
        ]

    # ---- loading -------------------------------------------------------

    @classmethod
    def from_artifacts(cls, config, model_paths: dict) -> "Detector":
        from . import features  # noqa: F401  (ensures FEATURE_NAMES import side effects)

        model = AnomalyModel.load(model_paths["model"], model_paths["calibration"])
        try:
            profile = Profile.load(model_paths["profile"])
        except (FileNotFoundError, ValueError):
            profile = Profile.empty()
        risk_engine = RiskEngine(model_paths["risk_weights"], config.severity)
        return cls(
            model,
            profile,
            risk_engine,
            model_version=model_paths["model_version"],
            detection_version=model_paths["detection_version"],
            child_record_types=config.scoring.child_record_types,
            asset_criticality=model_paths.get("asset_criticality", {}),
            default_criticality=model_paths.get("default_criticality", 0.5),
        )
