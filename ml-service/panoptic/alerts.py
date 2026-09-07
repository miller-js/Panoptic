"""The ``panoptic-alerts`` document: schema, index mapping, and builder.

One alert == one scored security-relevant event. The original source document is
retained verbatim under ``log`` for analyst drill-down. Numeric/keyword/date
fields that the API filters, sorts, or aggregates on are mapped explicitly;
everything under ``log`` stays dynamic (with ``ignore_dynamic_beyond_limit`` so
a wide auditd record can never reject the whole document).
"""

from __future__ import annotations

from datetime import datetime, timezone

from .context import EventContext
from .model import Scored
from .risk import RiskResult

ALERTS_MAPPING = {
    "settings": {
        "index.mapping.total_fields.limit": 2000,
        "index.mapping.total_fields.ignore_dynamic_beyond_limit": True,
    },
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "event": {
                "properties": {
                    "id": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "type": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "category": {"type": "keyword"},
                    "module": {"type": "keyword"},
                    "outcome": {"type": "keyword"},
                }
            },
            "host": {
                "properties": {
                    "name": {"type": "keyword"},
                    "ip": {"type": "ip", "ignore_malformed": True},
                    "criticality": {"type": "float"},
                }
            },
            "user": {
                "properties": {
                    "id": {"type": "long"},
                    "name": {"type": "keyword"},
                    "audit_id": {"type": "long"},
                    "audit_name": {"type": "keyword"},
                    "is_root": {"type": "boolean"},
                    "privilege_transition": {"type": "boolean"},
                }
            },
            "process": {
                "properties": {
                    "name": {"type": "keyword"},
                    "executable": {"type": "keyword"},
                    "command_line": {"type": "text"},
                    "args": {"type": "keyword"},
                    "pid": {"type": "long"},
                    "parent_pid": {"type": "long"},
                    "working_directory": {"type": "keyword"},
                    "audit_key": {"type": "keyword"},
                }
            },
            "network": {
                "properties": {
                    "direction": {"type": "keyword"},
                    "destination_ip": {"type": "ip", "ignore_malformed": True},
                    "destination_port": {"type": "long"},
                    "source_ip": {"type": "ip", "ignore_malformed": True},
                }
            },
            "detection": {
                "properties": {
                    "model": {"type": "keyword"},
                    "model_version": {"type": "keyword"},
                    "detection_version": {"type": "keyword"},
                    "anomaly_score": {"type": "float"},
                    "raw_score": {"type": "float"},
                    "confidence": {"type": "float"},
                    "prediction": {"type": "integer"},
                }
            },
            "risk": {
                "properties": {
                    "score": {"type": "integer"},
                    "severity": {"type": "keyword"},
                    "model": {"type": "keyword"},
                    "impact": {"type": "float"},
                    "exploitability": {"type": "float"},
                    "technical_severity": {"type": "float"},
                    "context_modifier": {"type": "float"},
                    "factors": {"type": "keyword"},
                    "components": {"type": "object", "enabled": True},
                }
            },
            "mitre": {
                "properties": {
                    "tactic": {"type": "keyword"},
                    "tactic_id": {"type": "keyword"},
                    "technique_id": {"type": "keyword"},
                    "technique_name": {"type": "keyword"},
                    "base_severity": {"type": "float"},
                    "confidence": {"type": "float"},
                }
            },
            "explanation": {
                "properties": {
                    "title": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}},
                    "summary": {"type": "text"},
                    "factors": {"type": "object", "enabled": False},
                }
            },
            "signals": {
                "properties": {
                    "recent_auth_failures": {"type": "integer"},
                    "recent_distinct_ports": {"type": "integer"},
                }
            },
            "log": {"type": "object", "dynamic": True},
        }
    },
}


def alert_id(ctx: EventContext) -> str:
    """Deterministic id so re-scoring the same event upserts instead of
    duplicating."""

    base = ctx.event_id or "noid"
    ts = ctx.timestamp.isoformat() if ctx.timestamp else "nots"
    return f"{ctx.host or 'nohost'}:{ts}:{base}:{ctx.record_type}"


def build_alert(
    ctx: EventContext,
    scored: Scored,
    risk: RiskResult,
    techniques: list,
    explanation: dict,
    *,
    model_version: str,
    detection_version: str,
    risk_model_name: str = "panoptic-risk-v1",
    signals: dict | None = None,
) -> dict:
    summary = ctx.to_summary()
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        **summary,
        "detection": {
            "model": "isolation_forest",
            "model_version": model_version,
            "detection_version": detection_version,
            "anomaly_score": scored.anomaly_score,
            "raw_score": scored.raw_score,
            "confidence": scored.confidence,
            "prediction": scored.prediction,
        },
        "risk": risk.to_dict(risk_model_name),
        "mitre": techniques,
        "explanation": explanation,
        "signals": signals or {
            "recent_auth_failures": ctx.recent_auth_failures,
            "recent_distinct_ports": ctx.recent_distinct_ports,
        },
        "log": ctx.raw,
    }
    if doc.get("network") is None:
        doc.pop("network", None)
    return doc
