"""Tests for audit logging."""

import pytest
from starfish_audit import AuditEntry, ConsoleAuditLogger, CallbackAuditLogger, NoopAuditLogger


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


@pytest.mark.asyncio
async def test_console_audit_logger(capsys):
    logger = ConsoleAuditLogger()
    await logger.record(_make_entry())
    captured = capsys.readouterr()
    assert "PULL" in captured.out
    assert "settings" in captured.out


@pytest.mark.asyncio
async def test_callback_audit_logger_sync():
    entries = []
    logger = CallbackAuditLogger(lambda e: entries.append(e))
    entry = _make_entry()
    await logger.record(entry)
    assert len(entries) == 1
    assert entries[0] == entry


@pytest.mark.asyncio
async def test_callback_audit_logger_async():
    entries = []
    async def async_cb(e: AuditEntry) -> None:
        entries.append(e)
    logger = CallbackAuditLogger(async_cb)
    entry = _make_entry()
    await logger.record(entry)
    assert len(entries) == 1
    assert entries[0] == entry


@pytest.mark.asyncio
async def test_noop_audit_logger(capsys):
    logger = NoopAuditLogger()
    await logger.record(_make_entry())
    captured = capsys.readouterr()
    assert captured.out == ""
