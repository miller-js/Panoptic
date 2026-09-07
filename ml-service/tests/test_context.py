from panoptic.context import build_context


def test_auditd_shape_uses_structured_fields(auditd_syscall_log):
    ctx = build_context(auditd_syscall_log)
    assert ctx.record_type == "SYSCALL"
    assert ctx.exe == "/usr/bin/sudo"
    assert ctx.comm == "sudo"
    assert ctx.uid == 0
    assert ctx.auid == 1000
    assert ctx.is_root is True
    assert ctx.privilege_transition is True          # auid 1000 -> uid 0
    assert ctx.auid_name == "stickyrice"
    assert ctx.event_id.endswith(":47679")  # epoch:sequence
    assert ctx.timestamp.year == 2026


def test_audit_key_is_cleaned_of_glued_enriched_field(auditd_syscall_log):
    ctx = build_context(auditd_syscall_log)
    assert ctx.audit_key == "privileged_commands"


def test_filestream_shape_falls_back_to_message(filestream_log):
    ctx = build_context(filestream_log)
    assert ctx.record_type == "BPF"
    assert ctx.host == "LinuxEndpoint"
    assert ctx.event_id.endswith(":4258")


def test_unusual_dir_and_process_classification():
    log = {
        "@timestamp": "2026-06-01T02:00:00Z",
        "auditd": {"log": {"record_type": "SYSCALL", "SYSCALL": "execve",
                           "exe": "/tmp/.x/payload", "comm": "payload", "uid": "1000", "auid": "1000"}},
    }
    ctx = build_context(log)
    assert ctx.exe_from_unusual_dir is True
    assert ctx.is_shell is False

    log["auditd"]["log"]["exe"] = "/usr/bin/bash"
    log["auditd"]["log"]["comm"] = "bash"
    ctx = build_context(log)
    assert ctx.is_shell is True
    assert ctx.exe_from_unusual_dir is False


def test_enrichment_merges_paths_and_argv():
    log = {
        "@timestamp": "2026-06-01T02:00:00Z",
        "auditd": {"log": {"record_type": "SYSCALL", "SYSCALL": "openat", "comm": "cat",
                           "exe": "/usr/bin/cat", "uid": "0", "auid": "1000"}},
    }
    ctx = build_context(log, {"paths": ["/etc/shadow"], "argv": ["cat", "/etc/shadow"]})
    assert ctx.paths == ("/etc/shadow",)
    assert ctx.touches_sensitive_path is True
    assert ctx.command_line == "cat /etc/shadow"


def test_unset_auid_sentinel_is_not_a_privilege_transition():
    # auditd writes an unset login uid as 4294967295 (unsigned -1); a boot-time
    # root process must not read as "user escalated to root"
    log = {
        "@timestamp": "2026-06-01T02:00:00Z",
        "user": {"id": "0", "audit": {"id": "4294967295"}},
        "auditd": {"log": {"record_type": "SYSCALL", "SYSCALL": "execve",
                           "exe": "/usr/lib/systemd/systemd", "comm": "systemd", "AUID": "unset"}},
    }
    ctx = build_context(log)
    assert ctx.auid == -1
    assert ctx.privilege_transition is False
    assert ctx.is_root_daemon is True
    assert ctx.auid_name is None


def test_auth_failure_detection():
    log = {
        "@timestamp": "2026-06-01T02:00:00Z",
        "auditd": {"log": {"record_type": "USER_AUTH", "res": "failed", "acct": "root", "addr": "203.0.113.1"}},
    }
    ctx = build_context(log)
    assert ctx.is_auth_event is True
    assert ctx.is_auth_failure is True
    assert ctx.is_remote is True
