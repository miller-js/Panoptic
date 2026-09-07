"""Template-based alert explanations.

No LLM. The explanation is assembled from the same features/context/technique
data the score is built from, so it can never say something the detection
logic didn't actually find. Output:

    {
      "title":   short headline picked from the dominant factor,
      "summary": one/two sentences of concrete detail,
      "factors": [{"label": ..., "value": ...}, ...]   # for the UI
    }
"""

from __future__ import annotations

from .context import EventContext
from .risk import RiskResult


def _rarity_word(rarity: float) -> str:
    if rarity >= 0.85:
        return "Very high"
    if rarity >= 0.6:
        return "High"
    if rarity >= 0.35:
        return "Moderate"
    return "Low"


def _privilege_phrase(ctx: EventContext) -> str:
    if ctx.privilege_transition and ctx.is_root:
        who = ctx.auid_name or (str(ctx.auid) if ctx.auid >= 0 else "a user")
        return f"Root (via privilege escalation from '{who}')"
    if ctx.is_root and not ctx.is_root_daemon:
        return "Root (interactive)"
    if ctx.is_root_daemon:
        return "Root (system service)"
    if ctx.privilege_transition:
        return "Elevated (privilege transition)"
    if ctx.is_login_user:
        return f"Standard user ({ctx.user_name or ctx.uid})"
    return "Unprivileged"


def _pick_title(ctx: EventContext, risk: RiskResult, techniques: list) -> str:
    f = set(risk.factors)
    if "repeated_auth_failure" in f:
        return "Repeated authentication failures"
    if "port_scanning" in f:
        return "Network scanning activity"
    if {"mitre_T1003.008"} & {t for t in f}:
        return "Credential store access"
    if "privilege_transition" in f and "rare_behaviour" in f:
        return "Rare privileged process execution"
    if "privilege_transition" in f:
        return "Privilege escalation"
    if ctx.is_remote and (ctx.is_network_tool or ctx.is_shell):
        return "Remote command execution"
    if "executable_outside_system_path" in f and ctx.action == "execve":
        return "Execution from a non-standard path"
    if "sensitive_file_access" in f:
        return "Sensitive file access"
    if "rare_behaviour" in f:
        return f"Rare {ctx.record_type.title()} activity"
    if techniques:
        return techniques[0]["technique_name"].split(":")[-1].strip()
    return f"Anomalous {ctx.record_type.title()} activity"


def _summary(ctx: EventContext, risk: RiskResult, anomaly_score: float, rarity: float, techniques: list) -> str:
    actor = ctx.process_name or ctx.exe or ctx.record_type.lower()
    user = ctx.user_name or (f"uid {ctx.uid}" if ctx.uid >= 0 else "an unknown user")
    host = ctx.host or "an unknown host"

    clauses = [f"{actor} was executed by {user} on {host}"]

    if ctx.command_line and ctx.command_line != actor:
        cmd = ctx.command_line
        clauses[0] += f" (`{cmd[:160]}{'…' if len(cmd) > 160 else ''}`)"

    if ctx.privilege_transition:
        origin = ctx.auid_name or (str(ctx.auid) if ctx.auid >= 0 else "another account")
        clauses.append(f"the action ran with escalated privileges from '{origin}'")
    if rarity >= 0.6:
        clauses.append(f"this executable is {_rarity_word(rarity).lower()} rarity for this user/host in the learned baseline")
    if ctx.recent_auth_failures >= 5:
        clauses.append(f"{ctx.recent_auth_failures} authentication failures preceded it in a short window")
    if ctx.is_remote:
        where = ctx.remote_addr or ctx.dest_ip
        clauses.append(f"the session originated remotely{f' from {where}' if where else ''}")
    if ctx.touches_sensitive_path:
        clauses.append("it touched sensitive files (" + ", ".join(p for p in ctx.sensitive_paths[:3]) + ")")

    text = clauses[0]
    if len(clauses) > 1:
        text += "; " + "; ".join(clauses[1:])
    text += f". Model anomaly score {round(anomaly_score * 100)}%."
    if techniques:
        ids = ", ".join(t["technique_id"] for t in techniques[:3])
        text += f" Mapped to ATT&CK {ids}."
    return text


def build_explanation(
    ctx: EventContext,
    risk: RiskResult,
    anomaly_score: float,
    confidence: float,
    techniques: list,
) -> dict:
    rarity = risk.components.get("rarity", 0.0)
    ui_factors = [
        {"label": "Anomaly confidence", "value": f"{round(confidence * 100)}%"},
        {"label": "Anomaly score", "value": f"{round(anomaly_score * 100)}%"},
        {"label": "Behaviour rarity", "value": _rarity_word(rarity)},
        {"label": "Privilege context", "value": _privilege_phrase(ctx)},
    ]
    if ctx.host:
        ui_factors.append({"label": "Host", "value": f"{ctx.host} (criticality {ctx.asset_criticality:.1f})"})
    if ctx.recent_auth_failures:
        ui_factors.append({"label": "Recent auth failures", "value": str(ctx.recent_auth_failures)})
    if techniques:
        ui_factors.append(
            {"label": "MITRE ATT&CK", "value": ", ".join(t["technique_id"] for t in techniques[:3])}
        )
    ui_factors.append({"label": "Risk score", "value": f"{risk.score} ({risk.severity.title()})"})

    return {
        "title": _pick_title(ctx, risk, techniques),
        "summary": _summary(ctx, risk, anomaly_score, rarity, techniques),
        "factors": ui_factors,
    }
