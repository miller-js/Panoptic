"""In-batch correlation of auditd child records onto their parent SYSCALL.

auditd emits one event as several lines sharing ``msg=audit(ts:SEQ)``:

    SYSCALL   -- the syscall, actor, exe, comm, key
    EXECVE    -- argv
    PROCTITLE -- the full command line (hex)
    CWD       -- working directory
    PATH      -- each file touched
    SOCKADDR  -- remote address (hex sockaddr)

The scoring loop reads a whole batch at once, so we can stitch these together
cheaply without cross-batch state. Only the SYSCALL (and other standalone
record types) get scored; the children just enrich it.
"""

from __future__ import annotations

import socket
import struct

from .context import audit_event_id
from .parser import decode_hex_field, parse_kv, extract_raw_audit_text, parse_proctitle, strip_control


def _execve_args(kv: dict, auditd_log: dict) -> list[str]:
    args: list[str] = []
    i = 0
    while True:
        key = f"a{i}"
        val = auditd_log.get(key, kv.get(key))
        if val is None:
            break
        decoded = strip_control(decode_hex_field(str(val)))
        if decoded:
            args.extend(decoded.split(" "))
        i += 1
    return [a for a in args if a]


def _parse_saddr(hex_saddr: str | None) -> tuple[str | None, int]:
    """Decode an auditd hex ``saddr`` blob into (ip, port). Handles AF_INET /
    AF_INET6; returns (None, -1) for anything else (AF_UNIX, malformed)."""

    if not hex_saddr:
        return None, -1
    try:
        raw = bytes.fromhex(hex_saddr.strip())
    except ValueError:
        return None, -1
    if len(raw) < 4:
        return None, -1
    family = struct.unpack_from("<H", raw, 0)[0]
    try:
        if family == socket.AF_INET and len(raw) >= 8:
            port = struct.unpack_from(">H", raw, 2)[0]
            ip = socket.inet_ntop(socket.AF_INET, raw[4:8])
            return ip, port
        if family == socket.AF_INET6 and len(raw) >= 28:
            port = struct.unpack_from(">H", raw, 2)[0]
            ip = socket.inet_ntop(socket.AF_INET6, raw[8:24])
            return ip, port
    except OSError:
        return None, -1
    return None, -1


def _record_type(log: dict) -> str:
    auditd = log.get("auditd") if isinstance(log.get("auditd"), dict) else {}
    auditd_log = auditd.get("log", {}) if isinstance(auditd.get("log"), dict) else {}
    kv = parse_kv(extract_raw_audit_text(log))
    return str(auditd_log.get("record_type") or kv.get("type") or "").upper()


def build_enrichment_map(logs: list[dict]) -> dict[str, dict]:
    """event_id -> {argv, proctitle, cwd, paths, dest_ip, dest_port}"""

    enrichment: dict[str, dict] = {}
    for log in logs:
        event_id = audit_event_id(log)
        if not event_id:
            continue
        rtype = _record_type(log)
        auditd = log.get("auditd") if isinstance(log.get("auditd"), dict) else {}
        auditd_log = auditd.get("log", {}) if isinstance(auditd.get("log"), dict) else {}
        kv = parse_kv(extract_raw_audit_text(log))
        slot = enrichment.setdefault(event_id, {"paths": []})

        if rtype == "EXECVE":
            args = _execve_args(kv, auditd_log)
            if args:
                slot["argv"] = args
                slot.setdefault("proctitle", " ".join(args))
        elif rtype == "PROCTITLE":
            pt = parse_proctitle(auditd_log.get("proctitle") or kv.get("proctitle"))
            if pt:
                slot["proctitle"] = pt
        elif rtype == "CWD":
            slot["cwd"] = decode_hex_field(auditd_log.get("cwd") or kv.get("cwd"))
        elif rtype == "PATH":
            name = decode_hex_field(auditd_log.get("name") or kv.get("name"))
            if name:
                slot["paths"].append(name)
        elif rtype == "SOCKADDR":
            ip, port = _parse_saddr(auditd_log.get("saddr") or kv.get("saddr"))
            if ip:
                slot["dest_ip"] = ip
                slot["dest_port"] = port
    return enrichment
