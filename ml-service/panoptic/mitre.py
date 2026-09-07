"""Rule-based MITRE ATT&CK technique tagging.

Deliberately a hand-written rule table, not an NLP/classifier:

* it is fully auditable -- every tag has a named, readable condition,
* technique IDs are real (Enterprise ATT&CK), never invented,
* when nothing matches with reasonable confidence we emit ``[]`` rather than a
  guess.

Each rule yields ``{tactic, tactic_id, technique_id, technique_name,
confidence}``. Multiple rules can fire -- the result is a de-duplicated list,
highest-confidence first. ``base_severity`` (0..1) is a rough "how bad is this
technique if real" used by the risk engine; it is *not* part of ATT&CK.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .context import EventContext

TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0011": "Command and Control",
}


@dataclass(frozen=True)
class Technique:
    tactic_id: str
    technique_id: str
    technique_name: str
    base_severity: float

    def tag(self, confidence: float) -> dict:
        return {
            "tactic": TACTICS.get(self.tactic_id, ""),
            "tactic_id": self.tactic_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "base_severity": self.base_severity,
            "confidence": round(float(confidence), 2),
        }


# --- technique catalogue (only IDs that actually exist in ATT&CK) -----------

T1059_004 = Technique("TA0002", "T1059.004", "Command and Scripting Interpreter: Unix Shell", 0.45)
T1059_006 = Technique("TA0002", "T1059.006", "Command and Scripting Interpreter: Python", 0.5)
T1071 = Technique("TA0011", "T1071", "Application Layer Protocol", 0.4)
T1105 = Technique("TA0011", "T1105", "Ingress Tool Transfer", 0.6)
T1571 = Technique("TA0011", "T1571", "Non-Standard Port", 0.55)
T1219 = Technique("TA0011", "T1219", "Remote Access Software", 0.6)
T1046 = Technique("TA0007", "T1046", "Network Service Discovery", 0.55)
T1018 = Technique("TA0007", "T1018", "Remote System Discovery", 0.35)
T1021_004 = Technique("TA0008", "T1021.004", "Remote Services: SSH", 0.5)
T1078 = Technique("TA0005", "T1078", "Valid Accounts", 0.4)
T1110 = Technique("TA0006", "T1110", "Brute Force", 0.7)
T1548_003 = Technique("TA0004", "T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", 0.45)
T1548_001 = Technique("TA0004", "T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid", 0.55)
T1136_001 = Technique("TA0003", "T1136.001", "Create Account: Local Account", 0.6)
T1098 = Technique("TA0003", "T1098", "Account Manipulation", 0.55)
T1003_008 = Technique("TA0006", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", 0.8)
T1552_004 = Technique("TA0006", "T1552.004", "Unsecured Credentials: Private Keys", 0.7)
T1053_003 = Technique("TA0003", "T1053.003", "Scheduled Task/Job: Cron", 0.55)
T1543_002 = Technique("TA0003", "T1543.002", "Create or Modify System Process: Systemd Service", 0.55)
T1547_006 = Technique("TA0003", "T1547.006", "Boot or Logon Autostart Execution: Kernel Modules and Extensions", 0.6)
T1562_001 = Technique("TA0005", "T1562.001", "Impair Defenses: Disable or Modify Tools", 0.75)
T1070_002 = Technique("TA0005", "T1070.002", "Indicator Removal: Clear Linux or Mac System Logs", 0.7)
T1070_003 = Technique("TA0005", "T1070.003", "Indicator Removal: Clear Command History", 0.6)
T1222_002 = Technique("TA0005", "T1222.002", "File and Directory Permissions Modification: Linux and Mac", 0.4)
T1204_002 = Technique("TA0002", "T1204.002", "User Execution: Malicious File", 0.4)


Rule = Callable[[EventContext], "float | None"]


def _rev_shell_indicator(ctx: EventContext) -> bool:
    cmd = (ctx.command_line or "").lower()
    return any(tok in cmd for tok in ("/dev/tcp/", "/dev/udp/", "-e /bin/sh", "-e /bin/bash", "bash -i", "sh -i", "mkfifo"))


def _pipe_to_shell(ctx: EventContext) -> bool:
    cmd = (ctx.command_line or "").lower()
    return ("curl" in cmd or "wget" in cmd) and ("| sh" in cmd or "| bash" in cmd or "|sh" in cmd or "|bash" in cmd)


def _has_path(ctx: EventContext, *needles: str) -> bool:
    return any(any(n in p for n in needles) for p in ctx.paths)


_WRITE_SYSCALLS = {
    "write", "pwrite64", "writev", "openat", "open", "creat", "unlink", "unlinkat",
    "rename", "renameat", "renameat2", "truncate", "ftruncate", "link", "linkat",
    "symlink", "symlinkat", "mknod", "mknodat",
}


def _writes_to(ctx: EventContext, *needles: str) -> bool:
    """A write-shaped syscall whose target path matches one of ``needles``."""

    if ctx.action not in _WRITE_SYSCALLS:
        return False
    return _has_path(ctx, *needles)


def _sudo_to_shell(ctx: EventContext) -> bool:
    """sudo whose target is an interactive shell / su -- the escalation
    pattern that matters, vs `sudo apt install` which is routine admin."""

    cmd = (ctx.command_line or "").lower()
    tokens = cmd.split()
    if len(tokens) >= 2 and tokens[0].endswith("sudo"):
        target = tokens[1].rsplit("/", 1)[-1]
        if target in {"su", "bash", "sh", "zsh", "dash", "-i", "-s"} or "-i" in tokens:
            return True
    return False


# Each entry: (Technique, predicate(ctx) -> confidence in [0,1] or None).
# ctx is an EventContext; ctx.recent_auth_failures / ctx.recent_distinct_ports
# carry batch-local rolling counts.
RULES: list[tuple[Technique, Rule]] = [
    # -- Execution ----------------------------------------------------------
    (T1059_004, lambda c: 0.6 if (c.is_shell and (c.privilege_transition or c.exe_from_unusual_dir or c.is_remote))
     else (0.4 if (c.is_shell and c.command_line) else None)),
    (T1059_006, lambda c: 0.6 if (c.is_interpreter and (c.process_name or "").startswith("python")
                                  and (c.exe_from_unusual_dir or c.is_remote)) else None),
    (T1204_002, lambda c: 0.4 if (c.exe_from_unusual_dir and c.action == "execve" and c.is_login_user) else None),
    # -- Reverse shell / C2 ----------------------------------------------
    (T1059_004, lambda c: 0.85 if _rev_shell_indicator(c) else None),
    (T1071, lambda c: 0.5 if _rev_shell_indicator(c) else None),
    (T1105, lambda c: 0.8 if _pipe_to_shell(c)
     else (0.55 if (c.process_name in {"wget", "curl"} and c.is_remote) else None)),
    (T1219, lambda c: 0.6 if c.process_name in {"teamviewer", "anydesk", "ngrok", "rustdesk"} else None),
    (T1571, lambda c: 0.5 if (1024 < c.dest_port and c.dest_port not in (3389, 8080, 8443) and c.is_network_tool) else None),
    # -- Discovery ------------------------------------------------------
    (T1046, lambda c: 0.8 if c.is_scanner else (0.5 if c.recent_distinct_ports >= 15 else None)),
    (T1018, lambda c: 0.35 if (c.process_name in {"ping", "arp", "fping"} and c.is_remote) else None),
    # -- Lateral movement / remote access ------------------------------
    (T1021_004, lambda c: 0.55 if (c.process_name in {"ssh", "sshpass"} and c.is_remote)
     else (0.5 if (c.record_type == "USER_LOGIN" and c.remote_addr and c.success) else None)),
    # -- Credential access --------------------------------------------
    (T1110, lambda c: 0.85 if (c.is_auth_failure and c.recent_auth_failures >= 5) else None),
    (T1003_008, lambda c: (0.8 if not c.is_root_daemon else 0.6) if _has_path(c, "/etc/shadow", "/etc/gshadow") else None),
    (T1552_004, lambda c: (0.7 if c.privilege_transition else 0.5)
     if _has_path(c, "id_rsa", "id_ed25519", "/.ssh/") else None),
    # -- Privilege escalation -------------------------------------
    (T1548_003, lambda c: 0.85 if (c.process_name == "sudo" and _sudo_to_shell(c))
     else (0.4 if c.record_type == "USER_CMD" and _sudo_to_shell(c) else None)),
    (T1548_001, lambda c: 0.55 if c.record_type == "BPRM_FCAPS" else None),
    # -- Persistence ---------------------------------------------
    (T1136_001, lambda c: 0.7 if (c.process_name in {"useradd", "adduser"} or c.record_type == "ADD_USER") else None),
    (T1098, lambda c: 0.6 if (c.process_name in {"usermod", "gpasswd", "chage"}
                              or c.record_type in {"ADD_GROUP", "GRP_MGMT"}) else None),
    (T1053_003, lambda c: 0.6 if (c.process_name == "crontab"
                                  or _writes_to(c, "/etc/cron", "/var/spool/cron/")) else None),
    (T1543_002, lambda c: 0.65 if _writes_to(c, "/etc/systemd/system/", "/lib/systemd/system/", "/run/systemd/system/", ".service")
     else (0.5 if (c.process_name in {"systemctl"} and c.privilege_transition
                   and any(t in (c.command_line or "") for t in (" enable ", " disable ", " mask ", "--now")))
           else None)),
    (T1547_006, lambda c: 0.7 if (c.process_name in {"insmod", "modprobe"}
                                  or c.action in {"init_module", "finit_module"}) else None),
    # -- Defense evasion ------------------------------------
    # Disabling audit/MAC is evasion; *loading* audit rules (auditctl -R) at
    # boot is routine, so require a disable-shaped command.
    (T1562_001, lambda c: 0.8 if (
        (c.process_name == "auditctl" and any(t in (c.command_line or "") for t in (" -e 0", " -e0", " -D")))
        or (c.process_name == "setenforce" and "0" in (c.command_line or ""))
        or (c.process_name in {"systemctl", "service"}
            and any(t in (c.command_line or "") for t in ("stop auditd", "disable auditd", "stop apparmor", "stop falcon")))
    ) else None),
    (T1070_002, lambda c: 0.7 if (_has_path(c, "/var/log/")
                                  and c.action in {"unlink", "unlinkat", "truncate", "ftruncate", "rename"}) else None),
    (T1070_003, lambda c: 0.65 if (_has_path(c, ".bash_history", ".zsh_history")
                                   and c.action in {"unlink", "unlinkat", "truncate", "ftruncate", "openat"}) else None),
    (T1222_002, lambda c: 0.4 if (c.process_name in {"chmod", "chown", "chattr"} and c.touches_sensitive_path) else None),
]


MIN_CONFIDENCE = 0.35


def map_techniques(ctx: EventContext, signals: dict | None = None) -> list[dict]:
    if signals:
        ctx.recent_auth_failures = signals.get("recent_auth_failures", ctx.recent_auth_failures)
        ctx.recent_distinct_ports = signals.get("recent_distinct_ports", ctx.recent_distinct_ports)

    best: dict[str, dict] = {}
    for technique, predicate in RULES:
        try:
            confidence = predicate(ctx)
        except Exception:
            confidence = None
        if not confidence or confidence < MIN_CONFIDENCE:
            continue
        existing = best.get(technique.technique_id)
        if existing is None or confidence > existing["confidence"]:
            best[technique.technique_id] = technique.tag(confidence)

    return sorted(best.values(), key=lambda t: t["confidence"], reverse=True)


def max_technique_severity(tags: list[dict]) -> float:
    if not tags:
        return 0.0
    return max(t.get("base_severity", 0.0) * (0.5 + 0.5 * t.get("confidence", 0.0)) for t in tags)
