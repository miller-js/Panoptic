"""Evaluate the detection pipeline against labelled synthetic telemetry.

    python evaluate.py                      # use artifacts/, print a report
    python evaluate.py --json eval.json     # also write machine-readable output
    python evaluate.py --alert-severity medium
    python evaluate.py --repeats 3          # more scenario instances

Limitations (important):

* The model is unsupervised; these labels are only used to *measure* it, never
  to train it.
* The "normal" scenario set is a tiny, clean slice of real host behaviour, so
  the false-positive rate here is optimistic. Cross-check with ``report.py``
  against live data.
* "Detected a simulated attack" is weaker evidence than "detected a real
  attack" -- the synthetic events are shaped by the same assumptions as the
  detectors.
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter, defaultdict

import config as cfg
from panoptic.context import build_context
from panoptic.detector import Detector
from panoptic.enrich import build_enrichment_map
from panoptic.model import AnomalyModel
from panoptic.profile import Profile
from panoptic.risk import RiskEngine
from panoptic.signals import RollingSignals
from panoptic import scenarios

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _load_detector(config: cfg.Config) -> Detector:
    model = AnomalyModel.load(cfg.MODEL_PATH, cfg.CALIBRATION_PATH)
    try:
        profile = Profile.load(cfg.PROFILE_PATH)
    except (FileNotFoundError, ValueError):
        profile = Profile.empty()
    engine = RiskEngine(cfg.load_risk_weights(), config.severity)
    return Detector(
        model,
        profile,
        engine,
        model_version=cfg.MODEL_VERSION,
        detection_version=cfg.DETECTION_VERSION,
        child_record_types=config.scoring.child_record_types,
    )


def _technique_matches(expected: str, tags: list[dict]) -> bool:
    if not expected:
        return True
    got = {t["technique_id"] for t in tags}
    if expected in got:
        return True
    # allow the parent technique to satisfy a sub-technique expectation
    parent = expected.split(".")[0]
    return parent in {g.split(".")[0] for g in got}


def evaluate(detector: Detector, events: list[tuple[dict, dict]], alert_rank: int) -> dict:
    logs = [e[0] for e in events]
    labels = [e[1] for e in events]
    enrichment = build_enrichment_map(logs)
    rolling = RollingSignals()
    child_types = detector.child_record_types

    tp = fp = tn = fn = 0
    by_scenario = defaultdict(lambda: {"total": 0, "detected": 0, "label": "normal"})
    anomaly_by_label = defaultdict(list)
    risk_by_label = defaultdict(list)
    severity_hist = Counter()
    technique_hits = {"expected": 0, "matched": 0}
    rows = []

    for log, label in zip(logs, labels):
        ctx = build_context(log, None)
        signals = rolling.update(ctx)
        if ctx.record_type in child_types:
            continue
        if ctx.event_id and ctx.event_id in enrichment:
            ctx = build_context(log, enrichment[ctx.event_id])
            ctx.recent_auth_failures = signals["recent_auth_failures"]
            ctx.recent_distinct_ports = signals["recent_distinct_ports"]

        det = detector.detect(ctx, signals)
        # An "alert" is a risk severity at or above the threshold. The raw
        # IsolationForest -1/1 label is an internal feature, not an alerting
        # decision on its own (it is far too noisy at contamination=auto).
        alerted = SEVERITY_RANK[det.risk.severity] >= alert_rank

        scenario = label["scenario"]
        by_scenario[scenario]["label"] = label["label"]
        by_scenario[scenario]["total"] += 1
        if alerted:
            by_scenario[scenario]["detected"] += 1

        anomaly_by_label[label["label"]].append(det.scored.anomaly_score)
        risk_by_label[label["label"]].append(det.risk.score)
        severity_hist[det.risk.severity] += 1

        if label["label"] == "malicious" and label["expect_alert"]:
            if alerted:
                tp += 1
            else:
                fn += 1
            if label["expect_technique"]:
                technique_hits["expected"] += 1
                if _technique_matches(label["expect_technique"], det.techniques):
                    technique_hits["matched"] += 1
        elif label["label"] == "normal":
            if alerted:
                fp += 1
            else:
                tn += 1

        rows.append({
            "scenario": scenario,
            "label": label["label"],
            "record_type": ctx.record_type,
            "process": ctx.process_name,
            "anomaly_score": det.scored.anomaly_score,
            "risk_score": det.risk.score,
            "severity": det.risk.severity,
            "alerted": alerted,
            "techniques": [t["technique_id"] for t in det.techniques],
        })

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    def _dist(values: list[float]) -> dict:
        if not values:
            return {}
        s = sorted(values)
        return {
            "n": len(s),
            "min": round(s[0], 3),
            "median": round(statistics.median(s), 3),
            "mean": round(statistics.fmean(s), 3),
            "p90": round(s[min(len(s) - 1, int(len(s) * 0.9))], 3),
            "max": round(s[-1], 3),
        }

    return {
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "false_positive_rate": round(fpr, 3),
        },
        "mitre": {
            **technique_hits,
            "accuracy": round(technique_hits["matched"] / technique_hits["expected"], 3)
            if technique_hits["expected"] else None,
        },
        "detection_rate_by_scenario": {
            name: {
                "label": v["label"],
                "rate": round(v["detected"] / v["total"], 3) if v["total"] else 0.0,
                "detected": v["detected"],
                "total": v["total"],
            }
            for name, v in sorted(by_scenario.items())
        },
        "anomaly_score_distribution": {k: _dist(v) for k, v in anomaly_by_label.items()},
        "risk_score_distribution": {k: _dist(v) for k, v in risk_by_label.items()},
        "severity_histogram": dict(severity_hist),
        "rows": rows,
    }


def print_report(result: dict, alert_severity: str) -> None:
    m = result["metrics"]
    c = result["confusion"]
    print("\n=== Panoptic detection evaluation ===")
    print(f"alert threshold: risk severity >= {alert_severity}\n")
    print("Classification (simulated labels):")
    print(f"  precision            {m['precision']:.3f}")
    print(f"  recall               {m['recall']:.3f}")
    print(f"  f1                   {m['f1']:.3f}")
    print(f"  false positive rate  {m['false_positive_rate']:.3f}")
    print(f"  confusion            TP={c['tp']} FP={c['fp']} TN={c['tn']} FN={c['fn']}")

    mi = result["mitre"]
    if mi["accuracy"] is not None:
        print(f"\nMITRE technique mapping: {mi['matched']}/{mi['expected']} = {mi['accuracy']:.3f}")

    print("\nDetection rate by scenario:")
    for name, v in result["detection_rate_by_scenario"].items():
        marker = "  " if v["label"] == "normal" else "! "
        print(f"  {marker}{name:<26} {v['label']:<10} {v['detected']}/{v['total']}  ({v['rate']:.0%})")

    print("\nAnomaly score distribution:")
    for lab, d in result["anomaly_score_distribution"].items():
        if d:
            print(f"  {lab:<10} n={d['n']:<4} median={d['median']:.3f} mean={d['mean']:.3f} p90={d['p90']:.3f} max={d['max']:.3f}")
    print("\nRisk score distribution:")
    for lab, d in result["risk_score_distribution"].items():
        if d:
            print(f"  {lab:<10} n={d['n']:<4} median={d['median']} mean={d['mean']} p90={d['p90']} max={d['max']}")
    print("\nSeverity histogram:", result["severity_histogram"])
    print()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--alert-severity", default="high", choices=list(SEVERITY_RANK))
    p.add_argument("--repeats", type=int, default=2)
    p.add_argument("--json", dest="json_out")
    args = p.parse_args()

    config = cfg.load_config()
    detector = _load_detector(config)
    events = scenarios.generate(repeats=args.repeats)
    result = evaluate(detector, events, SEVERITY_RANK[args.alert_severity])

    print_report(result, args.alert_severity)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(result, fh, indent=2)
        print(f"wrote {args.json_out}")


if __name__ == "__main__":
    main()
