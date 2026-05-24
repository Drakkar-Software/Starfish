"""Concrete audit loggers for the Starfish server.

The ``AuditEntry`` dataclass and ``AuditLogger`` base class live in
``starfish_protocol``; this module supplies the ready-made implementations.
"""

import inspect
from typing import Awaitable, Callable

from starfish_protocol import AuditEntry, AuditLogger


class ConsoleAuditLogger(AuditLogger):
    """Audit logger that writes to console."""

    async def record(self, entry: AuditEntry) -> None:
        status = "OK" if entry.success else "FAIL"
        identity = entry.identity or "anonymous"
        print(
            f"[Starfish:AUDIT] {entry.action.upper()} {entry.collection} "
            f"by {identity} → {status} ({entry.status_code})"
        )


class CallbackAuditLogger(AuditLogger):
    """Audit logger that delegates to a sync or async callback."""

    def __init__(self, callback: Callable[[AuditEntry], None | Awaitable[None]]) -> None:
        self._callback = callback

    async def record(self, entry: AuditEntry) -> None:
        result = self._callback(entry)
        if inspect.isawaitable(result):
            await result


class NoopAuditLogger(AuditLogger):
    """No-op audit logger (discards entries)."""

    async def record(self, entry: AuditEntry) -> None:
        pass


__all__ = ["ConsoleAuditLogger", "CallbackAuditLogger", "NoopAuditLogger"]
