"""Generic in-memory keyed store (non-persistent, process-lifetime).

Used by members / nodes / resource-requests for composable invite/request tracking.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Generic, TypeVar

T = TypeVar("T")


class KeyedStore(Generic[T]):
    """A Map-backed in-memory store with serialize/hydrate round-trip."""

    def __init__(self) -> None:
        self._map: dict[str, T] = {}

    def set(self, key: str, value: T) -> None:
        self._map[key] = value

    def get(self, key: str) -> T | None:
        return self._map.get(key)

    def clear(self, key: str = "") -> None:
        """Remove one entry by ``key``, or clear the entire store when called with no arg."""
        if key:
            self._map.pop(key, None)
        else:
            self._map.clear()

    def clear_all(self) -> None:
        """Clear all entries (convenience alias for ``clear()``)."""
        self._map.clear()

    def serialize(self) -> str:
        """Serialize the store to a JSON string."""
        return json.dumps(self._map)

    def hydrate(self, serialized: str) -> None:
        """Restore the store from a JSON string produced by :meth:`serialize`."""
        parsed = json.loads(serialized)
        if isinstance(parsed, dict):
            self._map = parsed


def create_keyed_store() -> KeyedStore[Any]:
    """Create a fresh :class:`KeyedStore`."""
    return KeyedStore()


class ComposedStore(Generic[T]):
    """A store whose keys are composed from multiple string parts.

    Usage::

        store = create_composed_store(lambda space_id, user_id: f"{space_id}:{user_id}")
        scoped = store.for_("my-space", "user-123")
        scoped.set(value)
        scoped.get()  # → value or None
    """

    def __init__(self, compose_key: Callable[..., str]) -> None:
        self._store: KeyedStore[T] = KeyedStore()
        self._compose_key = compose_key

    def for_(self, *parts: str) -> "_ScopedEntry[T]":
        key = self._compose_key(*parts)
        return _ScopedEntry(self._store, key)

    @property
    def store(self) -> KeyedStore[T]:
        return self._store


class _ScopedEntry(Generic[T]):
    def __init__(self, store: KeyedStore[T], key: str) -> None:
        self._store = store
        self._key = key

    def get(self) -> T | None:
        return self._store.get(self._key)

    def set(self, value: T) -> None:
        self._store.set(self._key, value)

    def clear(self) -> None:
        # Remove only this key's entry by setting map sans this key.
        # KeyedStore doesn't expose delete, so we rebuild the map.
        m = self._store._map
        m.pop(self._key, None)


def create_composed_store(compose_key: Callable[..., str]) -> ComposedStore[Any]:
    """Create a :class:`ComposedStore` with the given key compositor.

    Example::

        store = create_composed_store(lambda a, b: f"{a}:{b}")
    """
    return ComposedStore(compose_key)


__all__ = [
    "KeyedStore",
    "ComposedStore",
    "create_keyed_store",
    "create_composed_store",
]
