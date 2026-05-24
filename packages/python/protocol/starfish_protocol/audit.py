"""Audit logging contract — shared by the server host and the audit extension.

The ``AuditEntry`` dataclass and ``AuditLogger`` base class live in the protocol
package (the shared contract layer) so that ``starfish-server`` (the host) can
emit audit events and the extension package (``starfish-audit``) can supply
concrete loggers, both without a dependency cycle. The concrete loggers
(``ConsoleAuditLogger`` / ``CallbackAuditLogger`` / ``NoopAuditLogger``) live in
``starfish-audit``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


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

    async def record(self, entry: AuditEntry) -> None:
        raise NotImplementedError


__all__ = ["AuditEntry", "AuditLogger"]
