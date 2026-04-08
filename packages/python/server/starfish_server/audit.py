"""Audit logging for Starfish server operations."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable, Literal


@dataclass
class AuditEntry:
    """Entry recorded in the audit log."""
    timestamp: float
    action: Literal["pull", "push"]
    collection: str
    identity: str | None
    document_key: str
    success: bool
    status_code: int
    params: dict[str, str] = field(default_factory=dict)


class AuditLogger:
    """Audit logger interface."""

    def record(self, entry: AuditEntry) -> None:
        raise NotImplementedError


class ConsoleAuditLogger(AuditLogger):
    """Audit logger that writes to console."""

    def record(self, entry: AuditEntry) -> None:
        status = "OK" if entry.success else "FAIL"
        identity = entry.identity or "anonymous"
        print(
            f"[Starfish:AUDIT] {entry.action.upper()} {entry.collection} "
            f"by {identity} → {status} ({entry.status_code})"
        )


class CallbackAuditLogger(AuditLogger):
    """Audit logger that delegates to a callback."""

    def __init__(self, callback: Callable[[AuditEntry], None]) -> None:
        self._callback = callback

    def record(self, entry: AuditEntry) -> None:
        self._callback(entry)


class NoopAuditLogger(AuditLogger):
    """No-op audit logger (discards entries)."""

    def record(self, entry: AuditEntry) -> None:
        pass
