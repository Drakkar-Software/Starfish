"""In-memory and callback-based object stores."""

import inspect
from starfish_server.storage.base import AbstractObjectStore
from typing import Any, Awaitable, Callable


# Module-level backing store shared across all MemoryObjectStore instances.
_global_data: dict[str, str] = {}


class MemoryObjectStore(AbstractObjectStore):
    """Pure in-memory object store backed by a module-level global dict.

    All instances share the same module-level backing dict, so data written
    through one instance is immediately visible to every other instance — no
    explicit dependency injection needed during prototyping and development.

    Pass ``data={}`` to opt out of the shared dict and use an isolated store
    (recommended for unit tests)::

        # Global (shared) store — default
        store = MemoryObjectStore()

        # Isolated store — starts empty, independent of the global dict
        store = MemoryObjectStore(data={})
    """

    def __init__(self, data: dict[str, str] | None = None) -> None:
        self._data: dict[str, str] = _global_data if data is None else data
        self._binary: dict[str, bytes] = {}
        self._binary_meta: dict[str, str] = {}

    async def get_string(self, key: str) -> str | None:
        return self._data.get(key)

    async def put(
        self,
        key: str,
        body: str,
        *,
        content_type: str | None = None,  # noqa: ARG002 — interface parameter
        cache_control: str | None = None,  # noqa: ARG002 — interface parameter
    ) -> None:
        self._data[key] = body

    async def list_keys(
        self,
        prefix: str,
        *,
        start_after: str | None = None,
        limit: int | None = None,
    ) -> list[str]:
        keys = sorted(k for k in self._data if k.startswith(prefix))
        if start_after:
            keys = [k for k in keys if k > start_after]
        if limit:
            keys = keys[:limit]
        return keys

    async def get_bytes(self, key: str) -> tuple[bytes, str] | None:
        body = self._binary.get(key)
        if body is None:
            return None
        return body, self._binary_meta.get(key, "application/octet-stream")

    async def put_bytes(
        self,
        key: str,
        body: bytes,
        *,
        content_type: str,
        cache_control: str | None = None,  # noqa: ARG002
    ) -> None:
        self._binary[key] = body
        self._binary_meta[key] = content_type

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)
        self._binary.pop(key, None)
        self._binary_meta.pop(key, None)

    async def delete_many(self, keys: list[str]) -> None:
        for key in keys:
            self._data.pop(key, None)
            self._binary.pop(key, None)
            self._binary_meta.pop(key, None)


async def _call(fn: Callable[..., Any], *args: Any) -> Any:
    """Invoke ``fn`` with ``args``, awaiting the result if it is a coroutine."""
    result = fn(*args)
    if inspect.isawaitable(result):
        return await result
    return result


GetFn = Callable[[str], str | None | Awaitable[str | None]]
PutFn = Callable[[str, str], None | Awaitable[None]]
ListFn = Callable[[str, str | None, int | None], list[str] | Awaitable[list[str]]]
DeleteFn = Callable[[str], None | Awaitable[None]]


class CustomObjectStore(AbstractObjectStore):
    """Object store backed entirely by user-supplied callback functions.

    Each storage operation dispatches to the corresponding callback.
    Callbacks may be synchronous or ``async``. Omitted callbacks fall back to
    safe no-op / empty-result defaults.

    Use this to bridge Starfish to any external system (database, remote API,
    custom file format, …) without subclassing ``AbstractObjectStore``
    protocol::

        import json

        data: dict[str, str] = {}

        store = CustomObjectStore(
            on_get=lambda key: data.get(key),
            on_put=lambda key, body: data.update({key: body}),
            on_list=lambda prefix, start_after, limit: sorted(
                k for k in data if k.startswith(prefix)
            ),
            on_delete=lambda key: data.pop(key, None),
        )

    Async callbacks are also supported::

        store = CustomObjectStore(
            on_get=my_async_db.fetch,
            on_put=my_async_db.store,
        )
    """

    def __init__(
        self,
        *,
        on_get: GetFn | None = None,
        on_put: PutFn | None = None,
        on_list: ListFn | None = None,
        on_delete: DeleteFn | None = None,
    ) -> None:
        self._on_get = on_get
        self._on_put = on_put
        self._on_list = on_list
        self._on_delete = on_delete

    async def get_string(self, key: str) -> str | None:
        if self._on_get is None:
            return None
        return await _call(self._on_get, key)

    async def put(
        self,
        key: str,
        body: str,
        *,
        content_type: str | None = None,  # noqa: ARG002 — interface parameter
        cache_control: str | None = None,  # noqa: ARG002 — interface parameter
    ) -> None:
        if self._on_put is not None:
            await _call(self._on_put, key, body)

    async def list_keys(
        self,
        prefix: str,
        *,
        start_after: str | None = None,
        limit: int | None = None,
    ) -> list[str]:
        if self._on_list is None:
            return []
        return await _call(self._on_list, prefix, start_after, limit)

    async def delete(self, key: str) -> None:
        if self._on_delete is not None:
            await _call(self._on_delete, key)

    async def delete_many(self, keys: list[str]) -> None:
        for key in keys:
            await self.delete(key)
