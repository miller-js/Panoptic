from datetime import timedelta

from panoptic.context import build_context
from panoptic.enrich import build_enrichment_map, _parse_saddr
from panoptic.signals import RollingSignals


def _auth(ts, ok=False, host="h1", acct="root"):
    return build_context({
        "@timestamp": ts.isoformat().replace("+00:00", "Z"),
        "host": {"hostname": host},
        "auditd": {"log": {"record_type": "USER_AUTH", "acct": acct,
                           "res": "success" if ok else "failed", "addr": "203.0.113.1"}},
    })


def test_rolling_auth_failures_window(base_time):
    sig = RollingSignals()
    last = {}
    for i in range(6):
        last = sig.update(_auth(base_time + timedelta(minutes=i)))
    assert last["recent_auth_failures"] == 6
    # 15 minutes later, the early failures have aged out of the 10-min window
    later = sig.update(_auth(base_time + timedelta(minutes=20)))
    assert later["recent_auth_failures"] < 6


def test_rolling_failures_are_per_account(base_time):
    sig = RollingSignals()
    sig.update(_auth(base_time, acct="root"))
    sig.update(_auth(base_time + timedelta(seconds=1), acct="root"))
    other = sig.update(_auth(base_time + timedelta(seconds=2), acct="dev"))
    assert other["recent_auth_failures"] == 1


def test_enrichment_map_links_children_to_syscall():
    logs = [
        {"auditd": {"log": {"sequence": 42, "record_type": "SYSCALL", "SYSCALL": "openat",
                            "exe": "/usr/bin/cat", "comm": "cat"}}},
        {"auditd": {"log": {"sequence": 42, "record_type": "PATH", "name": "/etc/shadow"}}},
        {"auditd": {"log": {"sequence": 42, "record_type": "EXECVE", "a0": "cat", "a1": "/etc/shadow"}}},
    ]
    enr = build_enrichment_map(logs)
    assert enr["42"]["paths"] == ["/etc/shadow"]
    assert enr["42"]["argv"] == ["cat", "/etc/shadow"]


def test_parse_saddr_ipv4():
    # AF_INET (0x0002 LE), port 4444 (0x115c BE), 203.0.113.4
    blob = "02001" + "15c" + "cb007104" + "0000000000000000"
    ip, port = _parse_saddr("0200115ccb0071040000000000000000")
    assert ip == "203.0.113.4"
    assert port == 4444
