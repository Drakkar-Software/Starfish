"""Per-collection queue configuration (owned by the queuing plugin)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class QueueConfig:
    """Per-collection queue publishing configuration.

    Apps pass a ``{collection_name: QueueConfig}`` map to
    :func:`create_queuing_server_plugin`. Collections absent from that map
    publish nothing.
    """

    topic: str | None = None
    """Subject/topic to publish to. Defaults to the collection name."""

    include_params: bool = False
    """Include the resolved route path parameters in the published message."""

    include_body: bool = False
    """Include the pushed ``data`` object in the message (JSON collections only)."""
