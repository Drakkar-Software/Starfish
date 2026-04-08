"""Tests for audit logging."""

from starfish_server.audit import AuditEntry, ConsoleAuditLogger, CallbackAuditLogger, NoopAuditLogger


def _make_entry() -> AuditEntry:
    return AuditEntry(
        timestamp=1234,
        action="pull",
        collection="settings",
        identity="user-1",
        document_key="users/user-1/settings",
        success=True,
        status_code=200,
    )


def test_console_audit_logger(capsys):
    logger = ConsoleAuditLogger()
    logger.record(_make_entry())
    captured = capsys.readouterr()
    assert "PULL" in captured.out
    assert "settings" in captured.out


def test_callback_audit_logger():
    entries = []
    logger = CallbackAuditLogger(lambda e: entries.append(e))
    entry = _make_entry()
    logger.record(entry)
    assert len(entries) == 1
    assert entries[0] == entry


def test_noop_audit_logger(capsys):
    logger = NoopAuditLogger()
    logger.record(_make_entry())
    captured = capsys.readouterr()
    assert captured.out == ""
