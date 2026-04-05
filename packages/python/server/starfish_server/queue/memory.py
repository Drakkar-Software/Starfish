"""In-memory and callback-based queue implementations."""

import inspect
from typing import Any, Awaitable, Callable

from starfish_server.queue.base import AbstractQueue


class MemoryQueue(AbstractQueue):
    """In-memory queue that records published messages for testing.

    Every call to :meth:`publish` appends a ``(subject, payload)`` tuple
    to :attr:`messages`::

        queue = MemoryQueue()
        await queue.publish("posts", b'{"collection":"posts"}')
        assert len(queue.messages) == 1
    """

    def __init__(self) -> None:
        self.messages: list[tuple[str, bytes]] = []

    async def publish(self, subject: str, payload: bytes) -> None:
        self.messages.append((subject, payload))


async def _call(fn: Callable[..., Any], *args: Any) -> Any:
    """Invoke *fn* with *args*, awaiting the result if it is a coroutine."""
    result = fn(*args)
    if inspect.isawaitable(result):
        return await result
    return result


PublishFn = Callable[[str, bytes], None | Awaitable[None]]


class CustomQueue(AbstractQueue):
    """Queue backed by a user-supplied callback function.

    The callback may be synchronous or ``async``::

        queue = CustomQueue(on_publish=lambda subject, payload: print(subject))
    """

    def __init__(self, *, on_publish: PublishFn | None = None) -> None:
        self._on_publish = on_publish

    async def publish(self, subject: str, payload: bytes) -> None:
        if self._on_publish is not None:
            await _call(self._on_publish, subject, payload)
