from panoptic.context import build_context
from panoptic.profile import Profile


def _ctx(exe, host="h1", auid="1000"):
    return build_context({
        "@timestamp": "2026-06-01T09:00:00Z",
        "host": {"hostname": host},
        "auditd": {"log": {"record_type": "SYSCALL", "SYSCALL": "execve", "exe": exe,
                           "comm": exe.rsplit("/", 1)[-1], "uid": "1000", "auid": auid, "AUID": "dev"}},
    })


def test_common_behaviour_is_low_rarity():
    p = Profile.from_events([_ctx("/usr/bin/ls") for _ in range(200)])
    assert p.rarity("exe", "/usr/bin/ls") < 0.2


def test_unseen_behaviour_is_high_rarity():
    p = Profile.from_events([_ctx("/usr/bin/ls") for _ in range(200)])
    assert p.rarity("exe", "/tmp/never-seen") > 0.8


def test_rarity_monotonic_in_frequency():
    events = [_ctx("/usr/bin/ls") for _ in range(100)] + [_ctx("/usr/bin/curl") for _ in range(3)]
    p = Profile.from_events(events)
    assert p.rarity("exe", "/usr/bin/curl") > p.rarity("exe", "/usr/bin/ls")


def test_empty_profile_returns_neutral():
    assert Profile.empty().rarity("exe", "/anything") == 0.5


def test_roundtrip_serialisation(tmp_path):
    p = Profile.from_events([_ctx("/usr/bin/ls") for _ in range(20)])
    path = tmp_path / "profile.json"
    p.save(path)
    loaded = Profile.load(path)
    assert loaded.event_count == p.event_count
    assert abs(loaded.rarity("exe", "/usr/bin/ls") - p.rarity("exe", "/usr/bin/ls")) < 1e-6


def test_pair_rarity_host_scoped():
    events = [_ctx("/usr/bin/ls", host="web1") for _ in range(50)]
    p = Profile.from_events(events)
    assert p.rarity("host_exe", ("web1", "/usr/bin/ls")) < 0.3
    assert p.rarity("host_exe", ("db1", "/usr/bin/ls")) > 0.7
