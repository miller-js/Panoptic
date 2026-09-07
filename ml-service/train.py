"""Train (or retrain) the Panoptic anomaly model.

Explicit, on-demand -- never runs inside the scoring loop. Produces three
artifacts under ``artifacts/`` (or ``$PANOPTIC_ARTIFACTS_DIR``):

    model.pkl         scaler + IsolationForest pipeline (+ feature name list)
    calibration.json  sorted training decision_function scores (percentile map)
    profile.json      behavioural baseline frequency tables

Usage:
    python train.py                     # defaults from config / env
    python train.py --sample-size 60000 --contamination 0.03
    python train.py --dry-run           # train, print score distribution, don't save
"""

from __future__ import annotations

import argparse
import json
import logging

import numpy as np

import config as cfg
from elastic import ElasticClient
from panoptic.context import build_context
from panoptic.enrich import build_enrichment_map
from panoptic.features import FEATURE_NAMES, feature_vector
from panoptic.model import AnomalyModel
from panoptic.profile import Profile
from panoptic.signals import RollingSignals

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("panoptic.train")


def _parse_args() -> argparse.Namespace:
    config = cfg.load_config()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sample-size", type=int, default=config.train.sample_size)
    p.add_argument("--sample-seed", type=int, default=config.train.sample_seed)
    p.add_argument("--n-estimators", type=int, default=config.model.n_estimators)
    p.add_argument("--max-samples", type=int, default=config.model.max_samples)
    p.add_argument("--contamination", default=config.model.contamination)
    p.add_argument("--random-state", type=int, default=config.model.random_state)
    p.add_argument("--dry-run", action="store_true", help="don't write artifacts")
    return p.parse_args()


def build_training_set(logs: list[dict]) -> tuple[list[list[float]], Profile]:
    """Contexts -> profile (from ALL events) -> feature vectors (scorable only).

    The profile must see children too (they carry paths etc. via enrichment
    onto the parent, but rarity counts are keyed on exe/host/user which only
    the SYSCALL has -- so in practice children contribute little, which is
    fine).
    """

    enrichment = build_enrichment_map(logs)
    rolling = RollingSignals()
    child_types = set(cfg.load_config().scoring.child_record_types)

    contexts = []
    for lg in logs:
        host = (lg.get("host") or {}).get("hostname") or (lg.get("host") or {}).get("name")
        ctx = build_context(lg, None)
        signals = rolling.update(ctx)
        if ctx.record_type in child_types:
            continue
        if ctx.event_id and ctx.event_id in enrichment:
            ctx = build_context(lg, enrichment[ctx.event_id])
            ctx.recent_auth_failures = signals["recent_auth_failures"]
            ctx.recent_distinct_ports = signals["recent_distinct_ports"]
        contexts.append(ctx)

    profile = Profile.from_events(contexts)

    X = []
    for ctx in contexts:
        sig = {"recent_auth_failures": ctx.recent_auth_failures,
               "recent_distinct_ports": ctx.recent_distinct_ports}
        X.append(feature_vector(ctx, profile, sig))
    return X, profile


def main() -> None:
    args = _parse_args()
    config = cfg.load_config()

    client = ElasticClient(config.elastic)
    if not client.ping():
        raise SystemExit(f"cannot reach Elasticsearch at {config.elastic.addr}")

    log.info("sampling up to %d source docs (seed=%d)", args.sample_size, args.sample_seed)
    logs = client.scroll_sample(args.sample_size, args.sample_seed)
    log.info("got %d docs", len(logs))
    if len(logs) < 500:
        raise SystemExit("not enough data to train (need >= 500 scorable events)")

    X, profile = build_training_set(logs)
    log.info("built %d feature vectors over %d features; profile has %d events",
             len(X), len(FEATURE_NAMES), profile.event_count)

    model_kwargs = cfg.ModelConfig(
        n_estimators=args.n_estimators,
        max_samples=min(args.max_samples, len(X)),
        contamination=str(args.contamination),
        random_state=args.random_state,
    ).sklearn_kwargs()
    log.info("training IsolationForest %s", model_kwargs)

    model = AnomalyModel.train(X, model_kwargs)

    raw = model.calibration.sorted_scores
    anomaly_scores = np.array([s.anomaly_score for s in model.score_many(X)])
    pcts = np.percentile(anomaly_scores, [50, 75, 90, 95, 99, 100])
    log.info("anomaly_score distribution p50/p75/p90/p95/p99/max = %s",
             ", ".join(f"{v:.3f}" for v in pcts))
    log.info("raw decision_function min/median/max = %.4f / %.4f / %.4f",
             raw.min(), np.median(raw), raw.max())

    if args.dry_run:
        log.info("--dry-run: not writing artifacts")
        return

    cfg.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    model.save(cfg.MODEL_PATH, cfg.CALIBRATION_PATH)
    profile.save(cfg.PROFILE_PATH)
    if not cfg.RISK_WEIGHTS_PATH.exists():
        cfg.RISK_WEIGHTS_PATH.write_text(json.dumps(cfg.DEFAULT_RISK_WEIGHTS, indent=2))
    log.info("wrote %s, %s, %s", cfg.MODEL_PATH.name, cfg.CALIBRATION_PATH.name, cfg.PROFILE_PATH.name)


if __name__ == "__main__":
    main()
