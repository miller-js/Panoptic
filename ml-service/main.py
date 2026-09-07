"""Panoptic ML scoring service.

Loop: pull the next batch of unprocessed source logs, score the security-
relevant ones, bulk-write alerts to ``panoptic-alerts``, advance the cursor,
sleep. Model training is a separate explicit step -- see ``train.py``.
"""

from __future__ import annotations

import logging
import time

import config as cfg
from elastic import ElasticClient
from panoptic.alerts import ALERTS_MAPPING
from panoptic.detector import Detector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("panoptic.main")


def _model_paths(config: cfg.Config) -> dict:
    return {
        "model": cfg.MODEL_PATH,
        "calibration": cfg.CALIBRATION_PATH,
        "profile": cfg.PROFILE_PATH,
        "risk_weights": cfg.load_risk_weights(),
        "model_version": cfg.MODEL_VERSION,
        "detection_version": cfg.DETECTION_VERSION,
        "asset_criticality": cfg.load_asset_criticality(),
        "default_criticality": cfg.DEFAULT_ASSET_CRITICALITY,
    }


def run_cycle(client: ElasticClient, detector: Detector, batch_size: int) -> int:
    logs = client.fetch_unprocessed(batch_size)
    if not logs:
        return 0

    detections = detector.score_batch(logs)
    if detections:
        pairs = [
            (d.alert_id(), d.to_alert(detector.model_version, detector.detection_version))
            for d in detections
        ]
        indexed, errors = client.bulk_index_alerts(pairs)
        log.info("scored %d/%d events -> %d alerts (%d errors)", len(detections), len(logs), indexed, errors)
    else:
        log.info("consumed %d events, none scorable", len(logs))

    # Advance the cursor past everything we consumed (scored or not), so child
    # records and unscorable types don't get re-read forever.
    last = logs[-1].get("@timestamp")
    if last:
        client.write_cursor(last)
    return len(logs)


def main() -> None:
    config = cfg.load_config()
    client = ElasticClient(config.elastic)

    while not client.ping():
        log.warning("waiting for Elasticsearch at %s", config.elastic.addr)
        time.sleep(5)

    client.ensure_state_index()
    created = client.ensure_index(cfg.ALERTS_INDEX, ALERTS_MAPPING)
    if created:
        log.info("created %s with explicit mapping", cfg.ALERTS_INDEX)

    while not cfg.MODEL_PATH.exists():
        log.warning(
            "no model at %s -- run `python train.py` (or `docker compose run --rm ml-service python train.py`); retrying in 30s",
            cfg.MODEL_PATH,
        )
        time.sleep(30)

    detector = Detector.from_artifacts(config, _model_paths(config))
    log.info(
        "detector ready: model=%s detection=%s features=%d profile_events=%d",
        detector.model_version,
        detector.detection_version,
        len(detector.model.feature_names),
        detector.profile.event_count,
    )

    interval = config.scoring.loop_interval_seconds
    while True:
        try:
            consumed = run_cycle(client, detector, config.scoring.batch_size)
            if consumed == 0:
                log.info("no new logs; sleeping %ds", interval)
        except Exception:  # noqa: BLE001 -- keep the loop alive, log and retry
            log.exception("scoring cycle failed")
        time.sleep(interval)


if __name__ == "__main__":
    main()
