"""Normalise a raw Elasticsearch document into an :class:`EventContext`.

Everything downstream (features, MITRE rules, risk, explanations) reads from
``EventContext`` and never touches the raw document shape again. Structured ECS
fields written by Filebeat's auditd module are preferred; the hand-parsed
``key=value`` text is the fallback for the ``filestream`` shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .parser import (
    audit_epoch,
    audit_sequence,
    decode_hex_field,
    extract_raw_audit_text,
    parse_kv,
    parse_proctitle,
)

UNKNOWN_ID = -1

# Directories from which executables are unremarkable. Anything run from
# elsewhere (/tmp, /dev/shm, /home, /var/tmp, a cwd-relative path) is notable.
_SYSTEM_BIN_DIRS = ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/libexec/", "/usr/lib/")

_SHELLS = {"bash", "sh", "dash", "zsh", "ash", "ksh", "csh", "tcsh", "fish"}
_INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "php", "node", "nodejs", "lua", "awk", "gawk", "tclsh"}
_NET_TOOLS = {"nc", "ncat", "netcat", "socat", "curl", "wget", "ssh", "scp", "sftp", "rsync", "ftp", "tftp"}
_SCANNERS = {"nmap", "masscan", "zmap", "rustscan", "unicornscan"}
_CRED_TOOLS = {"passwd", "chpasswd", "gpasswd", "useradd", "adduser", "usermod", "userdel", "groupadd", "getent"}


# auditd writes an unset uid/auid as the unsigned representation of -1.
_UNSET_IDS = {-1, 4294967295, 0xFFFFFFFF}


def _to_int(value, default: int = UNKNOWN_ID) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return UNKNOWN_ID if n in _UNSET_IDS else n


# Translated-name fields auditd fills with a literal placeholder when unknown.
_UNSET_NAMES = {"unset", "?", "(unknown)", "unknown", "n/a"}


def _clean_name(value):
    if value is None:
        return None
    if str(value).strip().lower() in _UNSET_NAMES:
        return None
    return value


def _first(*values):
    for value in values:
        if value not in (None, "", []):
            return value
    return None


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.rstrip("/").rsplit("/", 1)[-1] or None


def _as_str(value) -> str | None:
    """ECS fields like ``event.action`` are sometimes a list, sometimes a
    scalar. Normalise to the first non-empty string."""

    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value in (None, ""):
        return None
    return str(value)


def audit_event_id(log: dict) -> str | None:
    """Stable id shared by all auditd records of one event.

    The auditd *sequence* number alone is NOT globally unique -- it cycles, so
    the same value recurs constantly across a 320k-doc historical set. The real
    event id is ``epoch:sequence`` from ``msg=audit(EPOCH:SEQ)``; we fall back to
    ``@timestamp:sequence`` when only the structured fields are present.
    """

    text = extract_raw_audit_text(log)
    seq = audit_sequence(text)
    epoch = audit_epoch(text)

    auditd = log.get("auditd")
    if seq is None and isinstance(auditd, dict):
        s = auditd.get("log", {}).get("sequence")
        seq = str(s) if s is not None else None
    if seq is None:
        return None

    if epoch is not None:
        return f"{epoch:.3f}:{seq}"
    ts = log.get("@timestamp")
    return f"{ts}:{seq}" if ts else str(seq)


@dataclass
class EventContext:
    raw: dict = field(repr=False)
    raw_text: str = ""
    event_id: str | None = None
    timestamp: datetime | None = None

    record_type: str = "UNKNOWN"
    action: str | None = None
    categories: tuple = ()
    module: str | None = None

    host: str | None = None
    host_ips: tuple = ()
    asset_criticality: float = 0.5

    uid: int = UNKNOWN_ID
    euid: int = UNKNOWN_ID
    auid: int = UNKNOWN_ID
    user_name: str | None = None
    auid_name: str | None = None
    session: str | None = None
    tty: str | None = None
    remote_addr: str | None = None
    acct: str | None = None

    exe: str | None = None
    comm: str | None = None
    proctitle: str | None = None
    argv: tuple = ()
    pid: int = UNKNOWN_ID
    ppid: int = UNKNOWN_ID
    parent_exe: str | None = None
    parent_comm: str | None = None

    syscall: str | None = None
    success: bool | None = None
    audit_key: str | None = None
    cwd: str | None = None
    paths: tuple = ()

    dest_ip: str | None = None
    dest_port: int = UNKNOWN_ID

    # Batch-local rolling signals, filled in by the scoring loop (see
    # panoptic/signals.py). Defaulted so a context is usable standalone.
    recent_auth_failures: int = 0
    recent_distinct_ports: int = 0

    # ---- derived convenience properties -------------------------------------

    @property
    def is_root_daemon(self) -> bool:
        """Root action with no login identity -- i.e. a system service, not a
        person who escalated. Lowers suspicion for some rules."""

        return self.is_root and self.auid == UNKNOWN_ID

    @property
    def is_root(self) -> bool:
        return self.euid == 0 or (self.euid == UNKNOWN_ID and self.uid == 0)

    @property
    def is_login_user(self) -> bool:
        ref = self.uid if self.uid != UNKNOWN_ID else self.auid
        return ref >= 1000

    @property
    def is_system_user(self) -> bool:
        ref = self.uid if self.uid != UNKNOWN_ID else self.auid
        return 0 < ref < 1000

    @property
    def privilege_transition(self) -> bool:
        """auid (login identity) differs from the acting uid -- the classic
        sudo / su / setuid escalation signature."""

        return (
            self.auid != UNKNOWN_ID
            and self.uid != UNKNOWN_ID
            and self.auid != self.uid
            and self.auid >= 1000
        )

    @property
    def process_name(self) -> str | None:
        return self.comm or _basename(self.exe)

    @property
    def command_line(self) -> str | None:
        if self.proctitle:
            return self.proctitle
        if self.argv:
            return " ".join(self.argv)
        return None

    @property
    def exe_from_system_dir(self) -> bool:
        if not self.exe:
            return False
        return self.exe.startswith(_SYSTEM_BIN_DIRS)

    @property
    def exe_from_unusual_dir(self) -> bool:
        if not self.exe or not self.exe.startswith("/"):
            return False
        return not self.exe.startswith(_SYSTEM_BIN_DIRS)

    @property
    def is_shell(self) -> bool:
        return (self.process_name or "") in _SHELLS

    @property
    def is_interpreter(self) -> bool:
        return (self.process_name or "") in _INTERPRETERS

    @property
    def is_network_tool(self) -> bool:
        return (self.process_name or "") in _NET_TOOLS

    @property
    def is_scanner(self) -> bool:
        return (self.process_name or "") in _SCANNERS

    @property
    def is_cred_tool(self) -> bool:
        return (self.process_name or "") in _CRED_TOOLS

    @property
    def is_auth_event(self) -> bool:
        return self.record_type in {
            "USER_AUTH",
            "USER_LOGIN",
            "USER_ACCT",
            "CRED_ACQ",
            "CRED_REFR",
            "LOGIN",
            "USER_START",
        }

    @property
    def is_auth_failure(self) -> bool:
        return self.is_auth_event and self.success is False

    @property
    def touches_sensitive_path(self) -> bool:
        return bool(self.sensitive_paths)

    @property
    def sensitive_paths(self) -> tuple:
        sensitive = []
        for path in self.paths:
            p = path.lower()
            if any(
                marker in p
                for marker in (
                    "/etc/shadow",
                    "/etc/passwd",
                    "/etc/sudoers",
                    "/etc/gshadow",
                    "/.ssh/",
                    "id_rsa",
                    "id_ed25519",
                    "authorized_keys",
                    "/etc/cron",
                    "/etc/systemd/system",
                    "/var/log/",
                    ".bash_history",
                    "/root/",
                    "/boot/",
                )
            ):
                sensitive.append(path)
        return tuple(sensitive)

    @property
    def is_remote(self) -> bool:
        if self.remote_addr and self.remote_addr not in ("?", "127.0.0.1", "::1"):
            return True
        if self.tty and "ssh" in self.tty:
            return True
        if self.dest_ip and not _is_private_or_local(self.dest_ip):
            return True
        return False

    def to_summary(self) -> dict:
        """Small dict used for the alert's event/host/user/process blocks."""

        return {
            "event": {
                "id": self.event_id,
                "timestamp": self.timestamp.isoformat() if self.timestamp else None,
                "type": self.record_type,
                "action": self.action or self.syscall,
                "category": list(self.categories),
                "module": self.module,
                "outcome": _outcome(self.success),
            },
            "host": {
                "name": self.host,
                "ip": list(self.host_ips),
                "criticality": self.asset_criticality,
            },
            "user": {
                "id": self.uid if self.uid != UNKNOWN_ID else None,
                "name": self.user_name,
                "audit_id": self.auid if self.auid != UNKNOWN_ID else None,
                "audit_name": self.auid_name,
                "is_root": self.is_root,
                "privilege_transition": self.privilege_transition,
            },
            "process": {
                "name": self.process_name,
                "executable": self.exe,
                "command_line": self.command_line,
                "args": list(self.argv),
                "pid": self.pid if self.pid != UNKNOWN_ID else None,
                "parent_pid": self.ppid if self.ppid != UNKNOWN_ID else None,
                "working_directory": self.cwd,
                "audit_key": self.audit_key,
            },
            "network": _network_block(self),
        }


def _outcome(success: bool | None) -> str | None:
    if success is True:
        return "success"
    if success is False:
        return "failure"
    return None


def _network_block(ctx: "EventContext") -> dict | None:
    if ctx.dest_ip is None and ctx.dest_port == UNKNOWN_ID and ctx.remote_addr is None:
        return None
    block: dict = {}
    if ctx.dest_ip:
        block["destination_ip"] = ctx.dest_ip
    if ctx.dest_port != UNKNOWN_ID:
        block["destination_port"] = ctx.dest_port
    if ctx.remote_addr:
        block["source_ip"] = ctx.remote_addr
    block["direction"] = "inbound" if ctx.remote_addr else "outbound"
    return block or None


def _is_private_or_local(ip: str) -> bool:
    if ip in ("127.0.0.1", "::1", "0.0.0.0"):
        return True
    if ip.startswith(("10.", "192.168.", "169.254.", "172.")):
        # 172.16.0.0/12 is private; other 172.x are not, but treat the whole
        # block as internal here -- lab telemetry, and getting this exactly
        # right is not worth an ipaddress import in the hot path.
        return True
    if ip.startswith("fe80") or ip.startswith("fc") or ip.startswith("fd"):
        return True
    return False


def _parse_success(kv: dict, auditd_log: dict) -> bool | None:
    for source in (auditd_log, kv):
        value = source.get("success") or source.get("res")
        if value is None:
            continue
        low = str(value).lower()
        if low in ("yes", "success", "1", "true"):
            return True
        if low in ("no", "failed", "fail", "0", "false"):
            return False
    return None


def _parse_timestamp(log: dict) -> datetime | None:
    ts = log.get("@timestamp")
    if not ts:
        return None
    try:
        parsed = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def build_context(
    log: dict,
    enrichment: dict | None = None,
    asset_criticality: float = 0.5,
) -> EventContext:
    enrichment = enrichment or {}
    raw_text = extract_raw_audit_text(log)
    kv = parse_kv(raw_text)

    auditd = log.get("auditd") if isinstance(log.get("auditd"), dict) else {}
    auditd_log = auditd.get("log", {}) if isinstance(auditd.get("log"), dict) else {}

    event = log.get("event", {}) if isinstance(log.get("event"), dict) else {}
    host = log.get("host", {}) if isinstance(log.get("host"), dict) else {}
    process = log.get("process", {}) if isinstance(log.get("process"), dict) else {}
    user = log.get("user", {}) if isinstance(log.get("user"), dict) else {}

    # Prefer the concrete syscall name (execve, openat, ...) over the auditd
    # module's generic event.action == "syscall".
    _event_action = _as_str(event.get("action"))
    if _event_action == "syscall":
        _event_action = None
    action = (
        _as_str(auditd_log.get("SYSCALL"))
        or _as_str(kv.get("SYSCALL"))
        or _event_action
    )
    record_type = (
        _first(
            _as_str(auditd_log.get("record_type")),
            _as_str(kv.get("type")),
            action.upper() if action else None,
        )
        or "UNKNOWN"
    )

    categories = event.get("category") or ()
    if isinstance(categories, str):
        categories = (categories,)

    uid = _to_int(_first(user.get("id"), auditd_log.get("uid"), kv.get("uid")))
    euid = _to_int(
        _first(
            (user.get("effective") or {}).get("id") if isinstance(user.get("effective"), dict) else None,
            auditd_log.get("euid"),
            kv.get("euid"),
        )
    )
    auid = _to_int(
        _first(
            (user.get("audit") or {}).get("id") if isinstance(user.get("audit"), dict) else None,
            auditd_log.get("auid"),
            kv.get("auid"),
        )
    )

    exe = _first(process.get("executable"), auditd_log.get("exe"), kv.get("exe"))
    comm = _first(process.get("name"), auditd_log.get("comm"), kv.get("comm"))
    proctitle = _first(
        enrichment.get("proctitle"),
        parse_proctitle(auditd_log.get("proctitle")),
        parse_proctitle(kv.get("proctitle")),
    )

    argv = tuple(enrichment.get("argv") or ())

    paths = tuple(
        enrichment.get("paths")
        or _collect_paths(auditd_log)
        or ()
    )

    parent = process.get("parent", {}) if isinstance(process.get("parent"), dict) else {}

    ctx = EventContext(
        raw=log,
        raw_text=raw_text,
        event_id=audit_event_id(log),
        timestamp=_parse_timestamp(log),
        record_type=str(record_type).upper(),
        action=action,
        categories=tuple(str(c) for c in categories),
        module=_as_str(event.get("module")) or _as_str((log.get("service") or {}).get("type")),
        host=_first(_as_str(host.get("hostname")), _as_str(host.get("name"))),
        host_ips=tuple(host.get("ip") or ()),
        asset_criticality=asset_criticality,
        uid=uid,
        euid=euid,
        auid=auid,
        user_name=_first(_clean_name(auditd_log.get("UID")), _clean_name(kv.get("UID")), _name_from_uid(uid)),
        auid_name=_first(_clean_name(auditd_log.get("AUID")), _clean_name(kv.get("AUID"))),
        session=_first(auditd_log.get("ses"), kv.get("ses")),
        tty=_first(auditd_log.get("tty"), kv.get("tty"), kv.get("terminal")),
        remote_addr=_first(enrichment.get("remote_addr"), auditd_log.get("addr"), kv.get("addr")),
        acct=_first(auditd_log.get("acct"), kv.get("acct")),
        exe=exe,
        comm=comm,
        proctitle=proctitle,
        argv=argv,
        pid=_to_int(_first(process.get("pid"), auditd_log.get("pid"), kv.get("pid"))),
        ppid=_to_int(_first(parent.get("pid"), auditd_log.get("ppid"), kv.get("ppid"))),
        parent_exe=_first(parent.get("executable"), enrichment.get("parent_exe")),
        parent_comm=_first(parent.get("name"), enrichment.get("parent_comm")),
        syscall=_as_str(auditd_log.get("SYSCALL")) or _as_str(kv.get("syscall")),
        success=_parse_success(kv, auditd_log),
        audit_key=_clean_key(_first(auditd_log.get("key"), kv.get("key"))),
        cwd=_first(enrichment.get("cwd"), decode_hex_field(auditd_log.get("cwd")), decode_hex_field(kv.get("cwd"))),
        paths=paths,
        dest_ip=enrichment.get("dest_ip"),
        dest_port=_to_int(enrichment.get("dest_port")),
    )
    return ctx


def _clean_key(value: str | None) -> str | None:
    """The naive whitespace parser sometimes glues the audit ``key`` to the
    following enriched field (``key="logins"\\x1dARCH=x86_64``). Trim it."""

    if not value:
        return None
    for sep in ("\x1d", '"', " "):
        if sep in value:
            value = value.split(sep, 1)[0]
    return value or None


def _collect_paths(auditd_log: dict) -> list[str]:
    paths = []
    items = auditd_log.get("paths") or auditd_log.get("path")
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and item.get("name"):
                paths.append(decode_hex_field(item["name"]))
            elif isinstance(item, str):
                paths.append(decode_hex_field(item))
    elif isinstance(items, str):
        paths.append(decode_hex_field(items))
    name = auditd_log.get("name")
    if isinstance(name, str):
        paths.append(decode_hex_field(name))
    return [p for p in paths if p]


# Minimal, offline uid -> name hints for the common system accounts so
# explanations read naturally even on the filestream shape (no translation).
_WELL_KNOWN_UIDS = {0: "root", 1: "daemon", 33: "www-data", 101: "systemd-network", 999: "systemd-coredump"}


def _name_from_uid(uid: int) -> str | None:
    return _WELL_KNOWN_UIDS.get(uid)
