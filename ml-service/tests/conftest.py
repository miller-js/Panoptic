import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Keep tests hermetic -- never touch a real cluster.
os.environ.setdefault("PANOPTIC_ES_ADDR", "http://localhost:59999")


@pytest.fixture
def auditd_syscall_log():
    """An auditd-module SYSCALL doc: sudo -> root, structured ECS fields."""

    return {
        "@timestamp": "2026-07-14T23:27:29.162Z",
        "process": {"name": "sudo", "executable": "/usr/bin/sudo", "pid": 67319, "parent": {"pid": 29152}},
        "host": {"hostname": "LinuxEndpoint", "name": "linuxendpoint", "ip": ["192.168.10.101"]},
        "user": {"id": "0", "effective": {"id": "0"}, "audit": {"id": "1000"}},
        "event": {
            "module": "auditd",
            "action": "syscall",
            "category": ["process"],
            "original": (
                'type=SYSCALL msg=audit(1784071649.162:47679): arch=c000003e syscall=59 success=yes '
                'exit=0 ppid=29152 pid=67319 auid=1000 uid=0 euid=0 tty=pts2 ses=4 comm="sudo" '
                'exe="/usr/bin/sudo" key="privileged_commands"\x1dARCH=x86_64 SYSCALL=execve '
                'AUID="stickyrice" UID="root"'
            ),
        },
        "auditd": {"log": {
            "sequence": 47679, "record_type": "SYSCALL", "SYSCALL": "execve",
            "exe": "/usr/bin/sudo", "comm": "sudo", "uid": "0", "auid": "1000", "euid": "0",
            "success": "yes", "tty": "pts2", "ses": "4",
            "key": 'privileged_commands"\x1dARCH=x86_64', "AUID": "stickyrice", "UID": "root",
        }},
    }


@pytest.fixture
def filestream_log():
    """A filestream-shape doc: raw line only in `message`, no structured fields."""

    return {
        "@timestamp": "2026-07-31T01:00:50.240Z",
        "message": "type=BPF msg=audit(1785459648.235:4258): prog-id=126 op=LOAD",
        "input": {"type": "filestream"},
        "host": {"hostname": "LinuxEndpoint", "ip": ["192.168.10.101"]},
    }


@pytest.fixture
def base_time():
    return datetime(2026, 6, 1, 3, 30, tzinfo=timezone.utc)


@pytest.fixture(scope="session")
def trained_model():
    """A real (tiny) AnomalyModel trained on synthetic 'normal' feature vectors
    plus noise, so score() / calibration behave realistically in tests."""

    import numpy as np
    from panoptic.model import AnomalyModel
    from panoptic.features import FEATURE_NAMES

    rng = np.random.default_rng(0)
    n_features = len(FEATURE_NAMES)
    # cluster of "normal": low-privilege, business hours, common processes
    normal = rng.normal(0.0, 0.4, size=(2000, n_features))
    normal[:, 0] = rng.integers(8, 18, size=2000)  # hour
    X = np.abs(normal).tolist()
    return AnomalyModel.train(X, {"n_estimators": 80, "max_samples": 256, "contamination": "auto",
                                  "random_state": 0, "n_jobs": 1})
