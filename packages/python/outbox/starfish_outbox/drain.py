"""Drain driver for an :class:`OutboxQueue`. Connectivity-agnostic by design: the
caller decides *when* to drain (typically on a reconnect signal), keeping the queue
free of any platform/connectivity dependency."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, TypeVar

from .queue import OutboxEntry, OutboxQueue

T = TypeVar("T")


@dataclass
class DrainResult:
    sent: int
    failed: int


async def drain_outbox(
    queue: OutboxQueue,
    send: Callable[[OutboxEntry], Awaitable[None]],
    *,
    max_attempts: int = 5,
) -> DrainResult:
    """One drain pass: for each ``queued`` entry (oldest first), claim it, run
    ``send``, then ``remove`` on success or ``record_failure`` on raise. ``claim``
    is single-shot, so concurrent drains never double-send. ``failed`` entries are
    skipped (awaiting a manual ``retry``)."""
    sent = 0
    failed = 0
    queued = [e for e in queue.get() if e.status == "queued"]
    for entry in queued:
        if not await queue.claim(entry.id):
            continue
        try:
            await send(entry)
            await queue.remove(entry.id)
            sent += 1
        except Exception:
            before = next((e for e in queue.get() if e.id == entry.id), None)
            await queue.record_failure(entry.id, max_attempts)
            after = next((e for e in queue.get() if e.id == entry.id), None)
            if after is not None and after.status == "failed" and (before is None or before.status != "failed"):
                failed += 1
    return DrainResult(sent=sent, failed=failed)
