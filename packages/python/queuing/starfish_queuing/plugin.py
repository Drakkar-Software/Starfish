"""Server plugin for the queuing extension (Python mirror).

Implements the ``after_write`` write-path hook from the ``ServerPlugin``
contract: after a successful push the server hands the plugin a
:class:`WriteEvent`; for any collection present in the plugin's ``collections``
map it builds a :class:`QueueMessage` and publishes it to the configured
:class:`AbstractQueue`. ``shutdown`` closes the queue during graceful shutdown.

The ``ServerPlugin``/``WriteEvent`` types live in ``starfish-protocol`` (the
shared contract layer), so this package needs no dependency on
``starfish-server`` — applications wire both packages at the top level.
"""

from __future__ import annotations

from typing import Mapping

from starfish_protocol.plugins import ServerPlugin, WriteEvent

from starfish_queuing.base import AbstractQueue
from starfish_queuing.config import QueueConfig
from starfish_queuing.publish import publish_change_event


def create_queuing_server_plugin(
    *,
    queue: AbstractQueue,
    collections: Mapping[str, QueueConfig],
) -> ServerPlugin:
    """Build a :class:`ServerPlugin` that publishes a change event to *queue*
    after every successful push to a configured collection."""

    async def _after_write(event: WriteEvent) -> None:
        cfg = collections.get(event.collection)
        if cfg is None:
            return
        await publish_change_event(queue, cfg, event)

    async def _shutdown() -> None:
        await queue.close()

    return ServerPlugin(
        name="starfish-queuing",
        after_write=_after_write,
        shutdown=_shutdown,
    )


__all__ = ["create_queuing_server_plugin"]
