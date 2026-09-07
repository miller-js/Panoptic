"""Panoptic ML detection package.

Pipeline stages, each independently testable:

    context   raw Elasticsearch doc  -> EventContext (normalised, shape-agnostic)
    features  EventContext           -> numeric feature vector + named features
    profile   historical events      -> behavioural baseline (frequency maps)
    model     feature vector         -> anomaly score (percentile-calibrated)
    mitre     EventContext           -> [ATT&CK technique, ...]   (rule-based)
    risk      all of the above       -> composite 0-100 security_risk_score
    explain   all of the above       -> human-readable explanation + factors
    alerts    all of the above       -> the panoptic-alerts document
"""

from .context import EventContext, build_context, audit_event_id

__all__ = ["EventContext", "build_context", "audit_event_id"]
