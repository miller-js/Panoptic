"""Distribution report over the live ``panoptic-alerts`` index.

    python report.py
    python report.py --assert-spread 0.5   # exit 1 if any single risk score
                                           # value holds > 50% of alerts

Exists to answer one question at a glance: are risk/anomaly scores actually
spread across the range, or clustered (the old "everything is 35" failure)?
"""

from __future__ import annotations

import argparse
import sys

import config as cfg
from elastic import ElasticClient


def _bar(count: int, total: int, width: int = 40) -> str:
    if total <= 0:
        return ""
    filled = int(round(width * count / total))
    return "#" * filled + "-" * (width - filled)


def fetch(client: ElasticClient) -> dict:
    body = {
        "size": 0,
        "track_total_hits": True,
        "aggs": {
            "risk_bands": {
                "range": {
                    "field": "risk.score",
                    "ranges": [
                        {"key": "0-19 informational", "from": 0, "to": 20},
                        {"key": "20-39 low", "from": 20, "to": 40},
                        {"key": "40-59 medium", "from": 40, "to": 60},
                        {"key": "60-79 high", "from": 60, "to": 80},
                        {"key": "80-100 critical", "from": 80, "to": 101},
                    ],
                }
            },
            "risk_values": {"terms": {"field": "risk.score", "size": 40, "order": {"_count": "desc"}}},
            "risk_stats": {"stats": {"field": "risk.score"}},
            "actionable": {
                "filter": {"range": {"risk.score": {"gte": 20}}},
                "aggs": {"values": {"terms": {"field": "risk.score", "size": 40, "order": {"_count": "desc"}}}},
            },
            "severity": {"terms": {"field": "risk.severity", "size": 10}},
            "anomaly_hist": {"histogram": {"field": "detection.anomaly_score", "interval": 0.1, "min_doc_count": 0}},
            "anomaly_stats": {"stats": {"field": "detection.anomaly_score"}},
            "techniques": {"terms": {"field": "mitre.technique_id", "size": 15}},
            "technique_names": {"terms": {"field": "mitre.technique_name", "size": 15}},
        },
    }
    return client.search(cfg.ALERTS_INDEX, body)


def render(resp: dict) -> tuple[str, float]:
    total = resp["hits"]["total"]["value"]
    aggs = resp["aggregations"]
    lines = [f"\n=== panoptic-alerts distribution report ===", f"total alerts: {total}\n"]

    rs = aggs["risk_stats"]
    lines.append(f"risk.score   min={rs['min']} avg={rs['avg']:.1f} max={rs['max']}")
    lines.append("\nrisk score bands:")
    for b in aggs["risk_bands"]["buckets"]:
        lines.append(f"  {b['key']:<20} {b['doc_count']:>7}  {_bar(b['doc_count'], total)}")

    top_values = aggs["risk_values"]["buckets"]
    distinct = len(top_values)
    top_share = (top_values[0]["doc_count"] / total) if (top_values and total) else 0.0
    lines.append(f"\ndistinct risk score values (top {distinct} shown); "
                 f"most common = {top_values[0]['key'] if top_values else 'n/a'} "
                 f"({top_share:.1%} of all alerts)")
    for b in top_values[:12]:
        lines.append(f"  {b['key']:>3}: {b['doc_count']:>7}  {_bar(b['doc_count'], total)}")

    # Big clusters of identical *informational* scores are fine (e.g. one
    # `apt upgrade` = thousands of near-identical low-risk child processes).
    # What must not collapse is the actionable (>= low) range.
    act = aggs["actionable"]
    act_total = act["doc_count"]
    act_values = act["values"]["buckets"]
    act_share = (act_values[0]["doc_count"] / act_total) if (act_values and act_total) else 0.0
    lines.append(f"\nactionable alerts (risk >= 20): {act_total}; "
                 f"most common score {act_values[0]['key'] if act_values else 'n/a'} "
                 f"({act_share:.1%} of those), {len(act_values)} distinct values")

    lines.append("\nseverity:")
    for b in aggs["severity"]["buckets"]:
        lines.append(f"  {b['key']:<15} {b['doc_count']:>7}  {_bar(b['doc_count'], total)}")

    ast = aggs["anomaly_stats"]
    if ast["count"]:
        lines.append(f"\ndetection.anomaly_score  min={ast['min']:.3f} avg={ast['avg']:.3f} max={ast['max']:.3f}")
    for b in aggs["anomaly_hist"]["buckets"]:
        lines.append(f"  {b['key']:.1f}-{b['key'] + 0.1:.1f}  {b['doc_count']:>7}  {_bar(b['doc_count'], total)}")

    names = {b["key"]: b["doc_count"] for b in aggs["technique_names"]["buckets"]}
    lines.append("\ntop MITRE ATT&CK techniques:")
    if not aggs["techniques"]["buckets"]:
        lines.append("  (none mapped)")
    for b in aggs["techniques"]["buckets"]:
        lines.append(f"  {b['key']:<12} {b['doc_count']:>6}")
    if names:
        lines.append("\n  names: " + "; ".join(f"{k} ({v})" for k, v in list(names.items())[:8]))

    return "\n".join(lines) + "\n", act_share


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--assert-spread", type=float, default=None,
                   help="exit non-zero if one risk score holds more than this fraction "
                        "of the actionable (risk >= 20) alerts")
    args = p.parse_args()

    client = ElasticClient(cfg.load_config().elastic)
    if not client.ping():
        raise SystemExit(f"cannot reach Elasticsearch at {client.es}")

    resp = fetch(client)
    text, act_share = render(resp)
    print(text)

    if args.assert_spread is not None and act_share > args.assert_spread:
        print(f"FAIL: one risk score holds {act_share:.1%} of actionable alerts "
              f"(> {args.assert_spread:.0%} threshold)")
        sys.exit(1)


if __name__ == "__main__":
    main()
