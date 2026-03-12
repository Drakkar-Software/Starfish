"""Object / blob storage interface."""


from typing import Protocol, runtime_checkable


@runtime_checkable
class IObjectStore(Protocol):
    """Storage backend interface.

    Implementations: S3, R2, in-memory (testing).
    """

    async def get_string(self, key: str) -> str | None:
        pass

    async def put(
        self,
        key: str,
        body: str,
        *,
        content_type: str | None = None,
        cache_control: str | None = None,
    ) -> None:
        pass

    async def list(
        self,
        prefix: str,
        *,
        start_after: str | None = None,
        limit: int | None = None,
    ) -> list[str]:
        pass

    async def delete(self, key: str) -> None:
        pass

    async def delete_many(self, keys: list[str]) -> None:
        pass
