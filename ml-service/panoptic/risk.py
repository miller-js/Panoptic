"""Composite security risk score (CVSS-*inspired*, not CVSS).

CVSS scores the severity of a *vulnerability*. These are *behavioural
detections*, so we borrow the shape -- Impact and Exploitability sub-scores
combined into a technical severity, then adjusted by environmental/contextual
factors -- but not the formula or the vector strings. The output field is
``security_risk_score`` (0-100); nothing here should be read as an official
CVSS value.

    impact          = w . (privilege, confidentiality, integrity, availability)
    exploitability  = w . (privilege_required, attack_complexity, auth_context, remote)
    technical       = 0.6 * impact + 0.4 * exploitability        (impact-weighted)
    context_mod     = base + a*anomaly + r*rarity + t*technique + s*(asset-0.5)
                      clamped to [min, max]
    security_risk_score = clamp(round(100 * technical * context_mod), 0, 100)

Every sub-factor is a documented 0..1 estimate derived from real event
features -- see the ``_*`` helpers. Two events differing in privilege, target
sensitivity, anomaly, rarity, or technique will get materially different
scores; that's the whole point.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .context import EventContext
from .mitre import max_technique_severity


def _dot(weights: dict, values: dict) -> float:
    total_w = sum(weights.values()) or 1.0
    return sum(weights[k] * values.get(k, 0.0) for k in weights) / total_w


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


# --- Impact-like factors -------------------------------------------------

def _privilege_impact(ctx: EventContext) -> float:
    if ctx.privilege_transition and ctx.is_root:
        return 1.0          # login user became root
    if ctx.is_root and not ctx.is_root_daemon:
        return 0.8          # interactive root
    if ctx.privilege_transition:
        return 0.6          # some escalation, not to root
    if ctx.is_root_daemon:
        return 0.4          # service running as root (routine but high-value)
    return 0.2


def _confidentiality_impact(ctx: EventContext) -> float:
    if any("/etc/shadow" in p or "id_rsa" in p or "id_ed25519" in p for p in ctx.paths):
        return 1.0
    if any(("/.ssh/" in p or ".bash_history" in p or "/etc/passwd" in p) for p in ctx.paths):
        return 0.7
    if ctx.is_network_tool and ctx.is_remote:
        return 0.5          # possible exfil channel
    if ctx.touches_sensitive_path:
        return 0.5
    return 0.15


def _integrity_impact(ctx: EventContext) -> float:
    write_syscalls = {"write", "openat", "open", "unlink", "unlinkat", "rename", "renameat",
                      "truncate", "ftruncate", "chmod", "fchmod", "fchmodat", "chown", "fchown",
                      "link", "linkat", "symlink", "symlinkat", "init_module", "finit_module"}
    persistence_paths = ("/etc/cron", "/etc/systemd", "/lib/systemd", "/etc/sudoers",
                         "/etc/passwd", "/root/.ssh", "authorized_keys", "/boot/")
    if any(any(m in p for m in persistence_paths) for p in ctx.paths):
        return 0.9
    if ctx.record_type in {"ADD_USER", "ADD_GROUP", "USER_MGMT", "GRP_MGMT", "ROLE_ASSIGN"}:
        return 0.8
    if ctx.record_type == "CONFIG_CHANGE":
        return 0.7
    if ctx.action in write_syscalls and ctx.privilege_transition:
        return 0.55
    if ctx.action in write_syscalls:
        return 0.3
    return 0.1


def _availability_impact(ctx: EventContext) -> float:
    if ctx.process_name in {"systemctl", "service", "kill", "killall", "pkill", "shutdown", "reboot", "init"}:
        if any(t in (ctx.command_line or "") for t in ("stop", "disable", "mask", "kill", "-9")):
            return 0.7
        return 0.4
    if ctx.record_type == "SERVICE_STOP":
        return 0.5
    if ctx.process_name in {"auditctl", "setenforce"}:
        return 0.6
    return 0.1


# --- Exploitability-like factors ----------------------------------------

def _privilege_required(ctx: EventContext) -> float:
    # Lower privilege required to perform the action == more exploitable.
    if ctx.is_login_user and not ctx.is_root:
        return 1.0
    if ctx.privilege_transition:
        return 0.7   # needed a password/sudo right, but a normal user has it
    if ctx.is_system_user:
        return 0.4
    if ctx.is_root_daemon:
        return 0.2
    return 0.5


def _attack_complexity(ctx: EventContext) -> float:
    # Low complexity (single interactive command) -> high score.
    if ctx.is_shell or ctx.is_interpreter or ctx.record_type in {"USER_CMD", "USER_LOGIN", "USER_AUTH"}:
        return 0.9
    if ctx.action == "execve":
        return 0.7
    return 0.4


def _auth_context(ctx: EventContext) -> float:
    if ctx.is_auth_failure and ctx.recent_auth_failures >= 5:
        return 1.0
    if ctx.is_auth_failure:
        return 0.5
    if ctx.record_type == "USER_LOGIN" and ctx.remote_addr:
        return 0.4
    return 0.1


def _remote(ctx: EventContext) -> float:
    if ctx.is_remote and (ctx.dest_ip or ctx.remote_addr):
        return 1.0
    if ctx.is_remote:
        return 0.7
    if ctx.dest_port > 0:
        return 0.3
    return 0.0


# --- rarity ----------------------------------------------------------------

def _behavioural_rarity(features: dict) -> float:
    """Max of the profile rarity features -- 'have we seen this before?'."""

    keys = ("host_exe_rarity", "user_exe_rarity", "exe_rarity", "user_host_rarity")
    values = [features.get(k, 0.0) for k in keys]
    return max(values) if values else 0.0


@dataclass
class RiskResult:
    score: int
    severity: str
    impact: float
    exploitability: float
    technical_severity: float
    context_modifier: float
    components: dict = field(default_factory=dict)
    factors: list = field(default_factory=list)

    def to_dict(self, model_name: str) -> dict:
        return {
            "score": self.score,
            "severity": self.severity,
            "model": model_name,
            "impact": round(self.impact, 3),
            "exploitability": round(self.exploitability, 3),
            "technical_severity": round(self.technical_severity, 3),
            "context_modifier": round(self.context_modifier, 3),
            "components": {k: round(v, 3) for k, v in self.components.items()},
            "factors": self.factors,
        }


# Human-readable factor tags surfaced on the alert.
def _factor_tags(ctx: EventContext, features: dict, anomaly_score: float, rarity: float, techniques: list) -> list:
    tags = []
    if ctx.privilege_transition:
        tags.append("privilege_transition")
    if ctx.is_root and not ctx.is_root_daemon:
        tags.append("interactive_root")
    if features.get("is_privileged_key"):
        tags.append("sensitive_audit_rule")
    if ctx.is_auth_failure:
        tags.append("auth_failure")
    if ctx.recent_auth_failures >= 5:
        tags.append("repeated_auth_failure")
    if rarity >= 0.85:
        tags.append("rare_behaviour")
    elif rarity >= 0.6:
        tags.append("uncommon_behaviour")
    if features.get("exe_unusual_dir"):
        tags.append("executable_outside_system_path")
    if ctx.is_shell:
        tags.append("shell_execution")
    if ctx.is_interpreter:
        tags.append("interpreter_execution")
    if ctx.is_scanner or ctx.recent_distinct_ports >= 15:
        tags.append("port_scanning")
    if ctx.is_remote:
        tags.append("remote_origin")
    if ctx.touches_sensitive_path:
        tags.append("sensitive_file_access")
    if features.get("is_offhours"):
        tags.append("off_hours")
    if anomaly_score >= 0.9:
        tags.append("model_high_anomaly")
    for technique in techniques[:2]:
        tags.append(f"mitre_{technique['technique_id']}")
    return tags


class RiskEngine:
    def __init__(self, weights: dict, severity_bands):
        self.w = weights
        self.bands = severity_bands

    def evaluate(
        self,
        ctx: EventContext,
        features: dict,
        anomaly_score: float,
        techniques: list,
    ) -> RiskResult:
        impact_values = {
            "privilege": _privilege_impact(ctx),
            "confidentiality": _confidentiality_impact(ctx),
            "integrity": _integrity_impact(ctx),
            "availability": _availability_impact(ctx),
        }
        exploit_values = {
            "privilege_required": _privilege_required(ctx),
            "attack_complexity": _attack_complexity(ctx),
            "auth_context": _auth_context(ctx),
            "remote": _remote(ctx),
        }
        impact = _dot(self.w["impact"], impact_values)
        exploitability = _dot(self.w["exploitability"], exploit_values)

        ts_w = self.w["technical_severity"]
        technical = (ts_w["impact"] * impact + ts_w["exploitability"] * exploitability) / (
            ts_w["impact"] + ts_w["exploitability"]
        )

        rarity = _behavioural_rarity(features)
        technique_severity = max_technique_severity(techniques)

        # A confidently-matched ATT&CK technique is a strong prior that this
        # behaviour is genuinely bad -- don't let a modest impact/exploitability
        # combo drag the technical severity below what the technique implies.
        if technique_severity > 0:
            technique_floor = self.w["technique_floor"]["base"] + self.w["technique_floor"]["scale"] * technique_severity
            technical = max(technical, min(technique_floor, 1.0))

        cm = self.w["context_modifier"]
        context_modifier = _clamp(
            cm["base"]
            + cm["anomaly"] * anomaly_score
            + cm["rarity"] * rarity
            + cm["technique"] * technique_severity
            + cm["asset"] * (ctx.asset_criticality - 0.5) * 2.0,
            cm["min"],
            cm["max"],
        )

        raw_score = 100.0 * technical * context_modifier
        score = int(round(_clamp(raw_score, 0, 100)))
        severity = self.bands.classify(score)

        components = {
            "anomaly": anomaly_score,
            "rarity": rarity,
            "technique_severity": technique_severity,
            **{f"impact.{k}": v for k, v in impact_values.items()},
            **{f"exploit.{k}": v for k, v in exploit_values.items()},
        }
        factors = _factor_tags(ctx, features, anomaly_score, rarity, techniques)

        return RiskResult(
            score=score,
            severity=severity,
            impact=impact,
            exploitability=exploitability,
            technical_severity=technical,
            context_modifier=context_modifier,
            components=components,
            factors=factors,
        )
