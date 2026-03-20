from abc import ABC, abstractmethod


class AbstractObjectStore(ABC):
    @abstractmethod
    async def get_string(self, key: str) -> str | None:
        raise NotImplementedError("get_string must be implemented")

    @abstractmethod
    async def put(
        self,
        key: str,
        body: str,
        *,
        content_type: str | None = None,
        cache_control: str | None = None,
    ) -> None:
        raise NotImplementedError("put must be implemented")

    @abstractmethod
    async def list_keys(
        self,
        prefix: str,
        *,
        start_after: str | None = None,
        limit: int | None = None,
    ) -> list[str]:
        raise NotImplementedError("list_keys must be implemented")

    async def get_bytes(self, key: str) -> tuple[bytes, str] | None:
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
    ) -> None:
        """Store raw bytes with an explicit content type.

        Only required for binary collections (``allowedMimeTypes`` without ``application/json``).
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support binary storage (put_bytes)"
        )

    @abstractmethod
    async def delete(self, key: str) -> None:
        raise NotImplementedError("delete must be implemented")

    @abstractmethod
    async def delete_many(self, keys: list[str]) -> None:
        raise NotImplementedError("delete_many must be implemented")
