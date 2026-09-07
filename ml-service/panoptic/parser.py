"""Raw auditd text helpers.

Filebeat delivers the same auditd data in two shapes (see CLAUDE.md):

* ``filestream`` input  -> raw line in ``message``
* ``auditd`` module     -> raw line in ``event.original`` (+ structured
  ``auditd.log.*``, ``process.*``, ``user.*`` ECS fields), ``message`` absent

``extract_raw_audit_text`` papers over that difference. ``parse_kv`` turns a raw
line into a flat dict. The structured ECS fields are preferred over re-parsing
text wherever they exist -- see :mod:`panoptic.context`.
"""

from __future__ import annotations

import re

# auditd separates the "enriched" trailing fields from the core record with an
# ASCII unit-separator (0x1d) rather than whitespace. Split on either.
_FIELD_SPLIT = re.compile(r"[\s\x1d]+")

_AUDIT_MSG_RE = re.compile(r"audit\((?P<epoch>\d+(?:\.\d+)?):(?P<seq>\d+)\)")

_HEXPAIR_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")


def extract_raw_audit_text(log: dict) -> str:
    message = log.get("message")
    if message:
        return message
    event = log.get("event")
    if isinstance(event, dict):
        return event.get("original") or ""
    return ""


def parse_kv(text: str) -> dict:
    """Split an audit line's ``key=value`` pairs into a flat dict.

    Values are stripped of surrounding quotes. Later occurrences of a key win
    (auditd's enriched section repeats some keys with translated values, e.g.
    ``UID="root"`` after ``uid=0`` -- we keep both under different case).
    """

    parsed: dict[str, str] = {}
    for part in _FIELD_SPLIT.split(text):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        if not key:
            continue
        parsed[key] = value.strip("\"'")
    return parsed


def audit_sequence(text: str) -> str | None:
    """Return the auditd event sequence id embedded in ``msg=audit(ts:seq)``."""

    match = _AUDIT_MSG_RE.search(text or "")
    return match.group("seq") if match else None


def audit_epoch(text: str) -> float | None:
    match = _AUDIT_MSG_RE.search(text or "")
    return float(match.group("epoch")) if match else None


def decode_hex_field(value: str | None) -> str | None:
    """auditd hex-encodes fields that contain spaces/newlines (proctitle, some
    PATH names, EXECVE args). Decode when it looks like hex, else return as-is."""

    if not value:
        return value
    candidate = value.strip()
    if len(candidate) >= 4 and len(candidate) % 2 == 0 and _HEXPAIR_RE.match(candidate):
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8", "replace")
        except ValueError:
            return value
        # cmdline-style fields use NUL (and occasionally other control bytes)
        # as argument separators -- turn them all into spaces
        return "".join(ch if ch >= " " else " " for ch in decoded).strip()
    return value


_CARET_CTRL = re.compile(r"\^[@-_]")


def strip_control(value: str | None) -> str | None:
    """Turn argument separators into spaces and collapse whitespace.

    auditd uses NUL between args in proctitle/cmdline fields. Depending on the
    ingestion path that reaches us either as a real ``\\x00`` byte or as the
    literal caret-notation string ``^@`` (Filebeat's auditd module renders
    control bytes that way). Handle both, plus other C0 caret notations.
    """

    if value is None:
        return None
    value = _CARET_CTRL.sub(" ", value)
    cleaned = "".join(ch if ch >= " " or ch == "\t" else " " for ch in value)
    return " ".join(cleaned.split()) or None


def parse_proctitle(raw: str | None) -> str | None:
    return strip_control(decode_hex_field(raw))
