from panoptic.context import build_context
from panoptic.features import FEATURE_NAMES, extract_features, feature_vector


def _log(**auditd):
    base = {"record_type": "SYSCALL", "SYSCALL": "execve", "uid": "1000", "auid": "1000"}
    base.update(auditd)
    return {"@timestamp": "2026-06-01T03:30:00Z", "host": {"hostname": "h1"}, "auditd": {"log": base}}


def test_vector_length_matches_names():
    ctx = build_context(_log(exe="/usr/bin/ls", comm="ls"))
    vec = feature_vector(ctx)
    assert len(vec) == len(FEATURE_NAMES)
    assert all(isinstance(v, float) for v in vec)


def test_offhours_and_weekend_flags():
    # 2026-06-01 is a Monday, 03:30 UTC -> off-hours, not weekend
    ctx = build_context(_log(exe="/usr/bin/ls", comm="ls"))
    feats = extract_features(ctx)
    assert feats["is_offhours"] == 1.0
    assert feats["is_weekend"] == 0.0


def test_privilege_and_shell_features():
    ctx = build_context(_log(exe="/usr/bin/bash", comm="bash", uid="0", auid="1000"))
    feats = extract_features(ctx)
    assert feats["is_root"] == 1.0
    assert feats["privilege_transition"] == 1.0
    assert feats["is_shell"] == 1.0


def test_signals_feed_recent_auth_failures():
    ctx = build_context({"@timestamp": "2026-06-01T03:30:00Z",
                         "auditd": {"log": {"record_type": "USER_AUTH", "res": "failed"}}})
    feats = extract_features(ctx, signals={"recent_auth_failures": 9})
    assert feats["auth_failure"] == 1.0
    assert feats["recent_auth_failures"] == 9.0


def test_features_never_raise_on_sparse_record():
    ctx = build_context({"@timestamp": "2026-06-01T03:30:00Z",
                         "auditd": {"log": {"record_type": "PROCTITLE"}}})
    feats = extract_features(ctx)
    assert len(feats) == len(FEATURE_NAMES)


def test_rarity_features_use_profile():
    from panoptic.profile import Profile

    common = [build_context(_log(exe="/usr/bin/ls", comm="ls")) for _ in range(50)]
    profile = Profile.from_events(common)

    common_ctx = build_context(_log(exe="/usr/bin/ls", comm="ls"))
    rare_ctx = build_context(_log(exe="/tmp/x", comm="x"))
    assert extract_features(rare_ctx, profile)["exe_rarity"] > extract_features(common_ctx, profile)["exe_rarity"]
