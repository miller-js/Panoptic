from panoptic.parser import (
    audit_sequence,
    decode_hex_field,
    extract_raw_audit_text,
    parse_kv,
    parse_proctitle,
)


def test_extract_prefers_message_then_event_original():
    assert extract_raw_audit_text({"message": "a"}) == "a"
    assert extract_raw_audit_text({"event": {"original": "b"}}) == "b"
    assert extract_raw_audit_text({}) == ""


def test_parse_kv_strips_quotes_and_splits_on_unit_separator():
    text = 'comm="sudo" exe="/usr/bin/sudo" key="privileged"\x1dARCH=x86_64 UID="root"'
    kv = parse_kv(text)
    assert kv["comm"] == "sudo"
    assert kv["exe"] == "/usr/bin/sudo"
    assert kv["ARCH"] == "x86_64"
    assert kv["UID"] == "root"


def test_parse_kv_ignores_tokens_without_equals():
    assert parse_kv("type=SYSCALL arch") == {"type": "SYSCALL"}


def test_audit_sequence():
    assert audit_sequence("type=SYSCALL msg=audit(1784071649.162:47679): x=1") == "47679"
    assert audit_sequence("no match") is None


def test_decode_hex_field_roundtrip():
    assert decode_hex_field("2f62696e2f7368") == "/bin/sh"
    assert decode_hex_field("plain text") == "plain text"
    assert decode_hex_field(None) is None


def test_parse_proctitle_decodes_and_normalises_whitespace():
    raw = "curl http://x/y".encode().hex()
    assert parse_proctitle(raw) == "curl http://x/y"


def test_parse_proctitle_handles_nul_separators():
    # real NUL bytes (hex-decoded path)
    raw = "/sbin/auditctl\x00-R\x00/etc/audit/audit.rules".encode().hex()
    assert parse_proctitle(raw) == "/sbin/auditctl -R /etc/audit/audit.rules"


def test_strip_control_handles_caret_notation():
    from panoptic.parser import strip_control

    # Filebeat's auditd module renders NUL as the literal string "^@"
    assert strip_control("/sbin/auditctl^@-R^@/etc/audit/audit.rules") == "/sbin/auditctl -R /etc/audit/audit.rules"
