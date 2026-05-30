"""Test helpers for the projection extension."""

from starfish_server.storage.memory import MemoryObjectStore as _MemoryObjectStore


class MemoryObjectStore(_MemoryObjectStore):
    """Isolated in-memory store for tests (fresh backing dict per instance)."""

    def __init__(self) -> None:
        super().__init__(data={})
