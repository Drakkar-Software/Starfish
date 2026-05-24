"""``starfish-queuing`` — change-event queuing extension.

Public surface: the ``AbstractQueue`` transport base, the in-process
``MemoryQueue`` and callback ``CustomQueue`` backends, the ``QueueMessage``
shape, the per-collection ``QueueConfig``, and ``create_queuing_server_plugin``
— a ``ServerPlugin`` whose ``after_write`` hook publishes a message after each
successful push.

``NatsQueue``/``NatsQueueOptions`` live in ``starfish_queuing.nats`` (require the
``nats`` optional extra) and are imported on demand.
"""

from starfish_queuing.base import AbstractQueue
from starfish_queuing.memory import MemoryQueue, CustomQueue
from starfish_queuing.message import QueueMessage
from starfish_queuing.config import QueueConfig


def __getattr__(name: str):
    """Lazy import of ``create_queuing_server_plugin`` (keeps the
    ``starfish_protocol.plugins`` import off the hot path for backend-only
    users) and of ``NatsQueue``/``NatsQueueOptions`` (keeps ``nats-py`` an
    optional dependency)."""
    if name == "create_queuing_server_plugin":
        from starfish_queuing.plugin import create_queuing_server_plugin as _p
        return _p
    if name in ("NatsQueue", "NatsQueueOptions"):
        from starfish_queuing import nats as _nats
        return getattr(_nats, name)
    raise AttributeError(f"module 'starfish_queuing' has no attribute {name!r}")


__all__ = [
    "AbstractQueue",
    "MemoryQueue",
    "CustomQueue",
    "QueueMessage",
    "QueueConfig",
    "create_queuing_server_plugin",
    "NatsQueue",
    "NatsQueueOptions",
]
