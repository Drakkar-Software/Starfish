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

    @abstractmethod
    async def delete(self, key: str) -> None:
        raise NotImplementedError("delete must be implemented")

    @abstractmethod
    async def delete_many(self, keys: list[str]) -> None:
        raise NotImplementedError("delete_many must be implemented")
