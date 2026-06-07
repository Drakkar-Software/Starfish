"""``starfish-outbox`` — a durable, per-identity offline **write-queue** (the
client-side complement to the server-side ``queuing`` extension).

Generic over the queued item: the caller owns
what an item is, supplies its dedup ``id``, and a ``send`` that performs the real
write. The queue handles persistence (write-through to a ``LocalCache``),
dedup-by-id, single-shot claim, attempt counting with auto-retry-then-fail,
crash-safe ``sending`` recovery, and subscriptions. :func:`drain_outbox` is
connectivity-agnostic — the caller triggers it on whatever reconnect signal it has.
"""

from starfish_outbox.queue import (
    LocalCache,
    OutboxEntry,
    OutboxQueue,
    OutboxStatus,
    reset_sending_to_queued,
)
from starfish_outbox.drain import DrainResult, drain_outbox

__all__ = [
    "OutboxQueue",
    "OutboxEntry",
    "OutboxStatus",
    "LocalCache",
    "reset_sending_to_queued",
    "drain_outbox",
    "DrainResult",
]
