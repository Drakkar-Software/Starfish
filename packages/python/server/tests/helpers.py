"""Test helpers for the Starfish server."""

from starfish_server.storage.memory import MemoryObjectStore as _MemoryObjectStore


class MemoryObjectStore(_MemoryObjectStore):
    """Isolated in-memory store for tests.

    Each instantiation creates a fresh, empty backing dict so tests do not
    share state with each other or with the module-level global store.
    """

    def __init__(self) -> None:
        super().__init__(data={})
