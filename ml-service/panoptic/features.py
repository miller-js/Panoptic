"""Feature engineering.

Each feature is a small pure function of an :class:`~panoptic.context.EventContext`
(plus an optional behavioural :class:`~panoptic.profile.Profile` and batch-local
``signals``). Features are registered in ``FEATURE_SPECS`` in a fixed order; that
order *is* the model's input contract, so append new features at the end and bump
``MODEL_VERSION``.

Why these features (grouped):

* **Temporal** -- ``hour``, ``is_offhours``, ``is_weekend``. Interactive intrusion
  activity skews toward nights/weekends when defenders aren't watching; most
  legitimate auditd volume on a workstation is business-hours automation.
* **Privilege** -- ``is_root``, ``privilege_transition``, ``is_privileged_key``.
  Root actions and login->root transitions (sudo/su) are where a compromise does
  damage; the audit ``key=`` tag marks rule-flagged sensitive syscalls.
* **Process shape** -- ``exe_depth``, ``exe_unusual_dir``, ``is_shell``,
  ``is_interpreter``, ``is_network_tool``, ``is_scanner``, ``proctitle_len``,
  ``proctitle_tokens``, ``arg_count``. Execution from ``/tmp``, long obfuscated
  command lines, and shells/interpreters/net tools spawned unusually are classic
  execution & C2 signals.
* **Authentication** -- ``auth_failure``, ``recent_auth_failures``. A single
  failure is noise; a burst is brute force / password spraying.
* **Network** -- ``is_remote``, ``dest_port_class``, ``recent_distinct_ports``.
  Remotely-originated activity and fan-out to many ports (scanning) matter.
* **Behavioural rarity** -- ``host_exe_rarity``, ``user_exe_rarity``,
  ``exe_rarity``, ``record_type_rarity``, ``user_host_rarity``. Computed from the
  training baseline: "have we ever seen *this user* run *this binary* on *this
  host*?". This is what gives Isolation Forest real variance to split on and is
  the single biggest fix for the collapsed-score problem -- the old vector was
  near-constant for ~80% of records.
"""

from __future__ import annotations

from typing import Callable

from .context import EventContext

# auditd rule keys that indicate the syscall tripped a deliberately-placed
# sensitive rule (these are conventional names from common audit rulesets).
_PRIVILEGED_KEYS = {
    "privileged_commands",
    "privileged",
    "identity",
    "logins",
    "sudoers",
    "sudo",
    "audit_rules",
    "audit-config",
    "power",
    "modules",
    "kernel_modules",
    "shadow",
    "passwd_changes",
    "perm_mod",
    "rootcmd",
}

# Rough "interestingness" classes for a destination port.
_SENSITIVE_PORTS = {22, 23, 3389, 445, 139, 5985, 5986}  # remote admin / SMB
_COMMON_PORTS = {80, 443, 53, 123, 587, 993, 995, 25}


class _NullProfile:
    """Stand-in when no baseline is available (early training, unit tests).

    Everything is 'moderately rare' so features stay finite and centred.
    """

    total = 0

    def rarity(self, _kind: str, _key) -> float:
        return 0.5

    def frequency(self, _kind: str, _key) -> int:
        return 0


NULL_PROFILE = _NullProfile()


def _hour(ctx: EventContext, *_):
    return float(ctx.timestamp.hour) if ctx.timestamp else 12.0


def _is_offhours(ctx: EventContext, *_):
    if not ctx.timestamp:
        return 0.0
    h = ctx.timestamp.hour
    return 1.0 if (h < 7 or h >= 19) else 0.0


def _is_weekend(ctx: EventContext, *_):
    if not ctx.timestamp:
        return 0.0
    return 1.0 if ctx.timestamp.weekday() >= 5 else 0.0


def _is_root(ctx: EventContext, *_):
    return 1.0 if ctx.is_root else 0.0


def _is_system_user(ctx: EventContext, *_):
    return 1.0 if ctx.is_system_user else 0.0


def _is_login_user(ctx: EventContext, *_):
    return 1.0 if ctx.is_login_user else 0.0


def _privilege_transition(ctx: EventContext, *_):
    return 1.0 if ctx.privilege_transition else 0.0


def _is_privileged_key(ctx: EventContext, *_):
    return 1.0 if (ctx.audit_key or "") in _PRIVILEGED_KEYS else 0.0


def _auth_failure(ctx: EventContext, *_):
    return 1.0 if ctx.is_auth_failure else 0.0


def _recent_auth_failures(ctx: EventContext, profile, signals: dict):
    return float(min(signals.get("recent_auth_failures", 0), 20))


def _proctitle_len(ctx: EventContext, *_):
    cmd = ctx.command_line or ""
    return float(min(len(cmd), 400))


def _proctitle_tokens(ctx: EventContext, *_):
    cmd = ctx.command_line or ""
    return float(min(len(cmd.split()), 50))


def _arg_count(ctx: EventContext, *_):
    return float(min(len(ctx.argv), 50))


def _exe_depth(ctx: EventContext, *_):
    return float(ctx.exe.count("/")) if ctx.exe else 0.0


def _exe_unusual_dir(ctx: EventContext, *_):
    return 1.0 if ctx.exe_from_unusual_dir else 0.0


def _is_shell(ctx: EventContext, *_):
    return 1.0 if ctx.is_shell else 0.0


def _is_interpreter(ctx: EventContext, *_):
    return 1.0 if ctx.is_interpreter else 0.0


def _is_network_tool(ctx: EventContext, *_):
    return 1.0 if ctx.is_network_tool else 0.0


def _is_scanner(ctx: EventContext, *_):
    return 1.0 if ctx.is_scanner else 0.0


def _has_sensitive_path(ctx: EventContext, *_):
    return 1.0 if ctx.touches_sensitive_path else 0.0


def _is_remote(ctx: EventContext, *_):
    return 1.0 if ctx.is_remote else 0.0


def _dest_port_class(ctx: EventContext, *_):
    port = ctx.dest_port
    if port < 0:
        return 0.0
    if port in _SENSITIVE_PORTS:
        return 3.0
    if port in _COMMON_PORTS:
        return 1.0
    if 0 < port < 1024:
        return 2.0
    return 1.5


def _recent_distinct_ports(ctx: EventContext, profile, signals: dict):
    return float(min(signals.get("recent_distinct_ports", 0), 50))


def _host_exe_rarity(ctx: EventContext, profile, *_):
    return profile.rarity("host_exe", (ctx.host, ctx.exe or ctx.comm))


def _user_exe_rarity(ctx: EventContext, profile, *_):
    return profile.rarity("user_exe", (ctx.auid_name or ctx.auid, ctx.exe or ctx.comm))


def _exe_rarity(ctx: EventContext, profile, *_):
    return profile.rarity("exe", ctx.exe or ctx.comm)


def _record_type_rarity(ctx: EventContext, profile, *_):
    return profile.rarity("record_type", ctx.record_type)


def _user_host_rarity(ctx: EventContext, profile, *_):
    return profile.rarity("user_host", (ctx.auid_name or ctx.auid, ctx.host))


# (name, function). Order is the model input contract.
FEATURE_SPECS: list[tuple[str, Callable]] = [
    ("hour", _hour),
    ("is_offhours", _is_offhours),
    ("is_weekend", _is_weekend),
    ("is_root", _is_root),
    ("is_system_user", _is_system_user),
    ("is_login_user", _is_login_user),
    ("privilege_transition", _privilege_transition),
    ("is_privileged_key", _is_privileged_key),
    ("auth_failure", _auth_failure),
    ("recent_auth_failures", _recent_auth_failures),
    ("proctitle_len", _proctitle_len),
    ("proctitle_tokens", _proctitle_tokens),
    ("arg_count", _arg_count),
    ("exe_depth", _exe_depth),
    ("exe_unusual_dir", _exe_unusual_dir),
    ("is_shell", _is_shell),
    ("is_interpreter", _is_interpreter),
    ("is_network_tool", _is_network_tool),
    ("is_scanner", _is_scanner),
    ("has_sensitive_path", _has_sensitive_path),
    ("is_remote", _is_remote),
    ("dest_port_class", _dest_port_class),
    ("recent_distinct_ports", _recent_distinct_ports),
    ("host_exe_rarity", _host_exe_rarity),
    ("user_exe_rarity", _user_exe_rarity),
    ("exe_rarity", _exe_rarity),
    ("record_type_rarity", _record_type_rarity),
    ("user_host_rarity", _user_host_rarity),
]

FEATURE_NAMES: list[str] = [name for name, _ in FEATURE_SPECS]


def extract_features(ctx: EventContext, profile=None, signals: dict | None = None) -> dict:
    """Return ``{feature_name: float}`` for one event."""

    profile = profile or NULL_PROFILE
    signals = signals or {}
    out = {}
    for name, fn in FEATURE_SPECS:
        try:
            out[name] = float(fn(ctx, profile, signals))
        except Exception:
            out[name] = 0.0
    return out


def feature_vector(ctx: EventContext, profile=None, signals: dict | None = None) -> list[float]:
    feats = extract_features(ctx, profile, signals)
    return [feats[name] for name in FEATURE_NAMES]
