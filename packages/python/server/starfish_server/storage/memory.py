"""In-memory and callback-based object stores."""

import hashlib
import inspect
from starfish_server.storage.base import AbstractObjectStore, StoreContext
from typing import Any, Awaitable, Callable


# Module-level backing store shared across all MemoryObjectStore instances.
_global_data: dict[str, str] = {}


def _etag_of(body: str) -> str:
    """Content-derived version tag for compare-and-swap. It is store-internal
    (never crosses the wire, never compared across languages), so any stable hash
    works. Deriving it from content means MemoryObjectStore instances sharing one
    backing dict agree on the etag with zero extra shared state. (ABA is not a
    concern for ``append_item``: an append strictly grows the element count, so
    the head content never returns to a prior value.)"""
    return hashlib.blake2b(body.encode("utf-8"), digest_size=16).hexdigest()


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

    async def get_string(self, key: str, *, context: StoreContext | None = None) -> str | None:  # noqa: ARG002
        return self._data.get(key)

    async def put(
        self,
        key: str,
        body: str,
        *,
        content_type: str | None = None,  # noqa: ARG002 — interface parameter
        cache_control: str | None = None,  # noqa: ARG002 — interface parameter
        context: StoreContext | None = None,  # noqa: ARG002
    ) -> None:
        self._data[key] = body

    async def get_with_etag(
        self, key: str, *, context: StoreContext | None = None  # noqa: ARG002
    ) -> tuple[str, str] | None:
        value = self._data.get(key)
        if value is None:
            return None
        return value, _etag_of(value)

    async def put_if_match(
        self,
        key: str,
        body: str,
        expected_etag: str | None,
        *,
        content_type: str | None = None,  # noqa: ARG002 — interface parameter
        cache_control: str | None = None,  # noqa: ARG002 — interface parameter
        context: StoreContext | None = None,  # noqa: ARG002
    ) -> str | None:
        current = self._data.get(key)
        current_etag = None if current is None else _etag_of(current)
        # Precondition failed → a concurrent writer changed the key. Do NOT overwrite.
        if current_etag != expected_etag:
            return None
        self._data[key] = body
        return _etag_of(body)

    async def list_keys(
        self,
        prefix: str,
        *,
        start_after: str | None = None,
        limit: int | None = None,
        context: StoreContext | None = None,  # noqa: ARG002
    ) -> list[str]:
        # Union both dicts: put() and put_bytes() share one logical key
        # namespace (same as the real S3/filesystem backends), so a
        # binary-written key must be listable too.
        all_keys = set(self._data) | set(self._binary)
        keys = sorted(k for k in all_keys if k.startswith(prefix))
        if start_after:
            keys = [k for k in keys if k > start_after]
        if limit:
            keys = keys[:limit]
        return keys

    async def get_bytes(self, key: str, *, context: StoreContext | None = None) -> tuple[bytes, str] | None:  # noqa: ARG002
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
        context: StoreContext | None = None,  # noqa: ARG002
    ) -> None:
        self._binary[key] = body
        self._binary_meta[key] = content_type

    async def delete(self, key: str, *, context: StoreContext | None = None) -> None:  # noqa: ARG002
        self._data.pop(key, None)
        self._binary.pop(key, None)
        self._binary_meta.pop(key, None)

    async def delete_many(self, keys: list[str], *, context: StoreContext | None = None) -> None:
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


def _accepts_ctx(fn: Callable[..., Any], base_arity: int) -> bool:
    """Return True if ``fn`` accepts at least ``base_arity + 1`` positional args.

    Detects whether the user's callback was written to receive a StoreContext
    as its last positional argument. Checked once at construction time and
    cached to avoid repeated introspection overhead.
    """
    try:
        sig = inspect.signature(fn)
        params = list(sig.parameters.values())
        # *args catches any number of positional args
        if any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params):
            return True
        positional = [
            p for p in params
            if p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.POSITIONAL_ONLY)
        ]
        return len(positional) >= base_arity + 1
    except (ValueError, TypeError):
        # Cannot introspect (e.g. some builtins, C extensions) — assume accepts ctx
        return True


GetFn = Callable[..., str | None | Awaitable[str | None]]
PutFn = Callable[..., None | Awaitable[None]]
ListFn = Callable[..., list[str] | Awaitable[list[str]]]
DeleteFn = Callable[..., None | Awaitable[None]]


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
        # Arity-sniff once at construction time for backward compatibility.
        # Callbacks written as ``lambda key: ...`` still work; ``lambda key, ctx: ...`` gets ctx.
        self._on_get_accepts_ctx = _accepts_ctx(on_get, 1) if on_get is not None else False
        self._on_put_accepts_ctx = _accepts_ctx(on_put, 2) if on_put is not None else False
        self._on_list_accepts_ctx = _accepts_ctx(on_list, 3) if on_list is not None else False
        self._on_delete_accepts_ctx = _accepts_ctx(on_delete, 1) if on_delete is not None else False

    async def get_string(self, key: str, *, context: StoreContext | None = None) -> str | None:
        if self._on_get is None:
            return None
        if self._on_get_accepts_ctx:
            return await _call(self._on_get, key, context)
        return await _call(self._on_get, key)

    async def put(
        self,
        key: str,
        body: str,
        *,
        content_type: str | None = None,  # noqa: ARG002 — interface parameter
        cache_control: str | None = None,  # noqa: ARG002 — interface parameter
        context: StoreContext | None = None,
    ) -> None:
        if self._on_put is not None:
            if self._on_put_accepts_ctx:
                await _call(self._on_put, key, body, context)
            else:
                await _call(self._on_put, key, body)

    async def list_keys(
        self,
        prefix: str,
        *,
        start_after: str | None = None,
        limit: int | None = None,
        context: StoreContext | None = None,
    ) -> list[str]:
        if self._on_list is None:
            return []
        if self._on_list_accepts_ctx:
            return await _call(self._on_list, prefix, start_after, limit, context)
        return await _call(self._on_list, prefix, start_after, limit)

    async def delete(self, key: str, *, context: StoreContext | None = None) -> None:
        if self._on_delete is not None:
            if self._on_delete_accepts_ctx:
                await _call(self._on_delete, key, context)
            else:
                await _call(self._on_delete, key)

    async def delete_many(self, keys: list[str], *, context: StoreContext | None = None) -> None:
        for key in keys:
            await self.delete(key, context=context)
