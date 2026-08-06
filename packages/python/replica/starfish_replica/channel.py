"""The pluggable sync seam: :class:`ReplicaChannel`.

Mirrors the TS package's ``channel.ts``. A :class:`ChannelScheduler` (see
``scheduler.py``) drives any number of channels on a schedule; a channel
knows only how to sync itself once, given a call context. The HTTP-pull path
(``http_channel.py``) is one channel implementation; ``space/mirror_channel.py``
is another.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Literal, Optional, Protocol, runtime_checkable

from starfish_replica.config import SyncTrigger

__all__ = [
    "ReplicaCallContext",
    "REPLICATOR_CTX",
    "ReplicaChannel",
    "ChannelSchedule",
    "ScheduledChannel",
    "SyncTrigger",
]


@dataclass(frozen=True)
class ReplicaCallContext:
    """Distinguishes a replication-driven call from a direct app call, so one
    shared data-access function can serve both call sites and branch on which
    it is.

    ``cancel`` is the Python stand-in for TS's ``AbortSignal`` — optional and
    unused by the HTTP channel; a channel that supports cancellation may check
    it between steps.
    """

    call_kind: Literal["replicator", "classic"] = "replicator"
    cancel: Optional[asyncio.Event] = None


REPLICATOR_CTX = ReplicaCallContext(call_kind="replicator")


@runtime_checkable
class ReplicaChannel(Protocol):
    """A single sync-able data path. Implementations: :class:`HttpReplicaChannel`
    (``http_channel.py``), :class:`SpaceMirrorChannel` (``space/mirror_channel.py``)."""

    name: str

    async def sync(self, ctx: ReplicaCallContext) -> None:
        """Perform one sync cycle. Raise on failure — the scheduler funnels
        exceptions to its ``on_error`` handler; a channel should not swallow
        its own errors."""
        ...


@dataclass
class ChannelSchedule:
    """When/how often a :class:`ReplicaChannel` should be synced."""

    triggers: list[SyncTrigger] = field(default_factory=lambda: [SyncTrigger.SCHEDULED])
    interval_ms: Optional[int] = None
    on_pull_min_interval_ms: Optional[int] = None


@dataclass
class ScheduledChannel:
    """A channel paired with its schedule — the unit :class:`ChannelScheduler` operates on."""

    channel: ReplicaChannel
    schedule: ChannelSchedule
