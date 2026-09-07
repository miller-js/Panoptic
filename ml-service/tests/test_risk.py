import config as cfg
from panoptic.context import build_context
from panoptic.features import extract_features
from panoptic.mitre import map_techniques
from panoptic.risk import RiskEngine


def _engine():
    return RiskEngine(cfg.load_risk_weights(), cfg.SeverityBands())


def _ctx(**fields):
    base = {"record_type": "SYSCALL", "SYSCALL": "execve", "uid": "1000", "auid": "1000"}
    base.update(fields)
    return build_context({"@timestamp": "2026-06-01T03:30:00Z", "host": {"hostname": "h1"},
                          "auditd": {"log": base}})


def _score(ctx, anomaly=0.5):
    feats = extract_features(ctx)
    techniques = map_techniques(ctx)
    return _engine().evaluate(ctx, feats, anomaly, techniques)


def test_score_in_range_and_severity_consistent():
    r = _score(_ctx(exe="/usr/bin/ls", comm="ls"))
    assert 0 <= r.score <= 100
    assert r.severity == cfg.SeverityBands().classify(r.score)


def test_privileged_rare_event_outranks_routine_event():
    routine = _score(_ctx(exe="/usr/bin/ls", comm="ls"), anomaly=0.2)

    ctx = _ctx(exe="/usr/bin/sudo", comm="sudo", uid="0", auid="1000", key="privileged_commands")
    ctx.argv = ("sudo", "su", "-")
    privileged = _score(ctx, anomaly=0.95)

    assert privileged.score > routine.score + 15


def test_anomaly_score_moves_the_result():
    ctx = _ctx(exe="/usr/bin/scp", comm="scp")
    low = _score(ctx, anomaly=0.1)
    high = _score(ctx, anomaly=0.99)
    assert high.score > low.score


def test_two_different_events_do_not_collapse_to_same_score():
    scores = {
        _score(_ctx(exe="/usr/bin/ls", comm="ls"), 0.3).score,
        _score(_ctx(exe="/usr/bin/systemctl", comm="systemctl", uid="0", auid="1000"), 0.6).score,
        _score(_ctx(exe="/usr/sbin/useradd", comm="useradd", uid="0", auid="1000", key="identity"), 0.8).score,
    }
    assert len(scores) == 3


def test_factors_reflect_context():
    ctx = _ctx(exe="/usr/bin/sudo", comm="sudo", uid="0", auid="1000")
    r = _score(ctx, anomaly=0.9)
    assert "privilege_transition" in r.factors
    assert "model_high_anomaly" in r.factors


def test_weights_are_configurable(monkeypatch, tmp_path):
    weights = cfg.load_risk_weights()
    weights["context_modifier"]["max"] = 0.3
    path = tmp_path / "risk_weights.json"
    path.write_text(__import__("json").dumps(weights))
    monkeypatch.setattr(cfg, "RISK_WEIGHTS_PATH", path)
    engine = RiskEngine(cfg.load_risk_weights(), cfg.SeverityBands())
    ctx = _ctx(exe="/usr/bin/sudo", comm="sudo", uid="0", auid="1000")
    r = engine.evaluate(ctx, extract_features(ctx), 0.99, map_techniques(ctx))
    assert r.context_modifier <= 0.3
