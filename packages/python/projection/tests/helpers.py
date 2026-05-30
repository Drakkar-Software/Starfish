"""Test helpers for the projection extension."""

from starfish_server.storage.base import StoreContext
from starfish_server.storage.memory import MemoryObjectStore as _MemoryObjectStore


class MemoryObjectStore(_MemoryObjectStore):
    """Isolated in-memory store for tests (fresh backing dict per instance)."""

    def __init__(self) -> None:
        super().__init__(data={})


class OneShotConflictStore(MemoryObjectStore):
    """In-memory store that injects a competing write to one key exactly once,
    between the plugin's pull and its push, forcing a single hash-mismatch retry.

    Arm with :meth:`arm`; the injection fires on the 2nd ``get_string`` of the
    armed key (push's internal read), then disarms itself.
    """

    def __init__(self) -> None:
        super().__init__()
        self._armed_key: str | None = None
        self._competing: str | None = None
        self._calls = 0

    def arm(self, key: str, competing: str) -> None:
        self._armed_key = key
        self._competing = competing
        self._calls = 0

    async def get_string(self, key: str, *, context: StoreContext | None = None) -> str | None:
        if key == self._armed_key:
            self._calls += 1
            if self._calls == 2 and self._competing is not None:
                await super().put(key, self._competing, context=context)
                self._competing = None
                self._armed_key = None
        return await super().get_string(key, context=context)
