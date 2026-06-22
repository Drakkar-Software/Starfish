"""Test helpers — in-memory KV adapter + shared key fixture."""

from __future__ import annotations

from starfish_spaces.config import KvAdapter


class MemoryKvAdapter:
    """An in-memory :class:`KvAdapter` for tests."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def get_item(self, key: str) -> str | None:
        return self._store.get(key)

    async def set_item(self, key: str, value: str) -> None:
        self._store[key] = value

    async def remove_item(self, key: str) -> None:
        self._store.pop(key, None)

    def get_all(self) -> dict[str, str]:
        return dict(self._store)
