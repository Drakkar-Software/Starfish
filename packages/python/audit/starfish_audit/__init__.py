"""``starfish-audit`` — audit logging extension.

Ready-made audit loggers for recording the server's pull/push access events.
The ``AuditEntry`` / ``AuditLogger`` contract lives in ``starfish_protocol``;
this package re-exports them alongside the concrete loggers for convenience.
"""

from starfish_protocol import AuditEntry, AuditLogger

from starfish_audit.audit import (
    CallbackAuditLogger,
    ConsoleAuditLogger,
    NoopAuditLogger,
)

__all__ = [
    "AuditEntry",
    "AuditLogger",
    "ConsoleAuditLogger",
    "CallbackAuditLogger",
    "NoopAuditLogger",
]
