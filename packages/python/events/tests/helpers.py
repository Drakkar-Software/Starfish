"""Test helpers for the starfish-events plugin tests."""

from __future__ import annotations

from starfish_server.storage.base import AbstractObjectStore, StoreContext
from starfish_server.storage.memory import MemoryObjectStore as _MemoryObjectStore


class MemoryObjectStore(_MemoryObjectStore):
    """Isolated in-memory store — fresh backing dict per instance (no module-level sharing)."""

    def __init__(self) -> None:
        super().__init__(data={})


class FailingBinaryStore(MemoryObjectStore):
    """In-memory store whose ``put_bytes`` always raises ``OSError``.

    Used to test that a ``put_bytes`` failure propagates as HTTP 500 so the
    SunGlasses SDK requeues the batch.
    """

    async def put_bytes(
        self,
        key: str,
        body: bytes,
        *,
        content_type: str,
        cache_control: str | None = None,
        context: StoreContext | None = None,
    ) -> None:
        raise OSError("simulated S3 write failure")


class NoBinaryStore(AbstractObjectStore):
    """Minimal store that does NOT override ``put_bytes``.

    Used to test the construction-time guard in ``create_events_server_plugin``.
    """

    async def get_string(self, key: str, *, context: StoreContext | None = None) -> str | None:
        return None

    async def put(
        self,
        key: str,
        body: str,
        *,
        content_type: str | None = None,
        cache_control: str | None = None,
        context: StoreContext | None = None,
    ) -> None:
        pass

    async def list_keys(
        self,
        prefix: str,
        *,
        start_after: str | None = None,
        limit: int | None = None,
        context: StoreContext | None = None,
    ) -> list[str]:
        return []

    async def delete(self, key: str, *, context: StoreContext | None = None) -> None:
        pass

    async def delete_many(self, keys: list[str], *, context: StoreContext | None = None) -> None:
        pass
