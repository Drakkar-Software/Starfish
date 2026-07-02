from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class StoreContext:
    """Request metadata forwarded to every ObjectStore method call.

    Available inside ``on_get``/``on_put``/``on_list``/``on_delete`` callbacks.
    ``identity`` and ``roles`` are ``None`` / empty for public routes and
    internal system callers (replica sync, config loader).
    """
    collection: str
    params: Mapping[str, str]
    identity: str | None
    roles: tuple[str, ...]
    action: str  # "pull" | "push" | "list" | "delete"
    namespace: str | None = field(default=None)


class AbstractObjectStore(ABC):
    @abstractmethod
    async def get_string(self, key: str, *, context: "StoreContext | None" = None) -> str | None:
        raise NotImplementedError("get_string must be implemented")

    @abstractmethod
    async def put(
        self,
        key: str,
        body: str,
        *,
        content_type: str | None = None,
        cache_control: str | None = None,
        context: "StoreContext | None" = None,
    ) -> None:
        raise NotImplementedError("put must be implemented")

    @abstractmethod
    async def list_keys(
        self,
        prefix: str,
        *,
        start_after: str | None = None,
        limit: int | None = None,
        context: "StoreContext | None" = None,
    ) -> list[str]:
        """Return EVERY key under ``prefix``, in ascending lexicographic order,
        unless ``limit`` caps the count. The segmented append-only log depends on
        both guarantees: it lists all of a document's chunk keys in one call (no
        ``limit``) and binary-searches them by string compare, so a backend that
        truncates (e.g. an S3 page cap) or returns keys out of order would yield
        incomplete or misordered data. Custom backends must paginate fully and sort.
        """
        raise NotImplementedError("list_keys must be implemented")

    async def get_bytes(self, key: str, *, context: "StoreContext | None" = None) -> tuple[bytes, str] | None:
        """Retrieve raw bytes and the stored content-type.

        Returns ``(body, content_type)`` or ``None`` if the key does not exist.
        Only required for binary collections (``allowedMimeTypes`` without ``application/json``).
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support binary storage (get_bytes)"
        )

    async def put_bytes(
        self,
        key: str,
        body: bytes,
        *,
        content_type: str,
        cache_control: str | None = None,
        context: "StoreContext | None" = None,
    ) -> None:
        """Store raw bytes with an explicit content type.

        Only required for binary collections (``allowedMimeTypes`` without ``application/json``).
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support binary storage (put_bytes)"
        )

    async def get_with_etag(
        self, key: str, *, context: "StoreContext | None" = None
    ) -> "tuple[str, str] | None":
        """OPTIONAL compare-and-swap support (paired with :meth:`put_if_match`).

        Read the current value together with an opaque version tag. Returns
        ``(value, etag)`` or ``None`` when the key is absent.

        A backend that overrides BOTH this and :meth:`put_if_match` gains
        cross-instance concurrency safety for append-only writes (see
        :func:`append_item`): the head write becomes an atomic compare-and-swap
        that FAILS instead of silently overwriting a concurrent write from
        another server instance sharing the same bucket. Backends that do not
        override them keep last-write-wins — safe for a single instance, but a
        shared bucket may drop a concurrent instance's append.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support conditional writes (get_with_etag)"
        )

    async def put_if_match(
        self,
        key: str,
        body: str,
        expected_etag: str | None,
        *,
        content_type: str | None = None,
        cache_control: str | None = None,
        context: "StoreContext | None" = None,
    ) -> "str | None":
        """OPTIONAL atomic conditional write (paired with :meth:`get_with_etag`).

        Store ``body`` only if the key's current version matches
        ``expected_etag`` — or, when ``expected_etag`` is ``None``, only if the
        key does not yet exist. Returns the new etag on success, or ``None`` when
        the precondition failed because a concurrent writer changed the key.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support conditional writes (put_if_match)"
        )

    @abstractmethod
    async def delete(self, key: str, *, context: "StoreContext | None" = None) -> None:
        raise NotImplementedError("delete must be implemented")

    @abstractmethod
    async def delete_many(self, keys: list[str], *, context: "StoreContext | None" = None) -> None:
        raise NotImplementedError("delete_many must be implemented")
