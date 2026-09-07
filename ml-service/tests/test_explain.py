import config as cfg
from panoptic.context import build_context
from panoptic.explain import build_explanation
from panoptic.features import extract_features
from panoptic.mitre import map_techniques
from panoptic.risk import RiskEngine


def _explain(ctx, anomaly=0.9, confidence=0.85):
    feats = extract_features(ctx)
    techniques = map_techniques(ctx)
    risk = RiskEngine(cfg.load_risk_weights(), cfg.SeverityBands()).evaluate(ctx, feats, anomaly, techniques)
    return build_explanation(ctx, risk, anomaly, confidence, techniques), risk


def test_explanation_has_title_summary_factors():
    ctx = build_context({"@timestamp": "2026-06-01T03:30:00Z", "host": {"hostname": "h1"},
                         "auditd": {"log": {"record_type": "SYSCALL", "SYSCALL": "execve",
                                            "exe": "/usr/bin/sudo", "comm": "sudo", "uid": "0", "auid": "1000",
                                            "AUID": "dev"}}})
    expl, risk = _explain(ctx)
    assert expl["title"]
    assert "sudo" in expl["summary"]
    assert any(f["label"] == "Risk score" for f in expl["factors"])
    assert f"{risk.score}" in expl["factors"][-1]["value"]


def test_summary_mentions_real_values_only():
    ctx = build_context({"@timestamp": "2026-06-01T03:30:00Z", "host": {"hostname": "web7"},
                         "auditd": {"log": {"record_type": "USER_AUTH", "res": "failed", "addr": "203.0.113.9"}}})
    ctx.recent_auth_failures = 11
    expl, _ = _explain(ctx)
    assert "11 authentication failures" in expl["summary"]
    assert "web7" in expl["summary"]


def test_bruteforce_title():
    ctx = build_context({"@timestamp": "2026-06-01T03:30:00Z", "host": {"hostname": "h1"},
                         "auditd": {"log": {"record_type": "USER_AUTH", "res": "failed", "addr": "203.0.113.9"}}})
    ctx.recent_auth_failures = 8
    expl, _ = _explain(ctx)
    assert expl["title"] == "Repeated authentication failures"
