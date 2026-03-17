"""Types for the Starfish client SDK."""


from typing import Any, Callable, Protocol

from starfish_protocol.types import PullResult, PushSuccess, Timestamps


class ConflictError(Exception):
    """Push conflict error (HTTP 409 — hash mismatch)."""

    def __init__(self, server_response: str = "") -> None:
        self.server_response = server_response
        super().__init__(f"hash_mismatch: {server_response}" if server_response else "hash_mismatch")


class StarfishHttpError(Exception):
    """HTTP error from the Starfish server."""

    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {body}")


class AuthProvider(Protocol):
    async def __call__(
        self, *, method: str, path: str, body: str | None
    ) -> dict[str, str]:
        pass


class DataSigner(Protocol):
    async def __call__(self, data: str) -> str:
        pass


ConflictResolver = Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
