"""Test helpers for the queuing extension."""

from starfish_server.storage.memory import MemoryObjectStore as _MemoryObjectStore


class MemoryObjectStore(_MemoryObjectStore):
    """Isolated in-memory store for tests.

    Each instantiation creates a fresh, empty backing dict so tests do not
    share state with each other.
    """

    def __init__(self) -> None:
        super().__init__(data={})
