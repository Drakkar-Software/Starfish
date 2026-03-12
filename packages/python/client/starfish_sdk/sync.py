"""High-level sync manager with automatic conflict resolution."""

import asyncio
import random
from typing import Any

from starfish_protocol.hash import stable_stringify
from starfish_protocol.merge import deep_merge
from starfish_protocol.types import PullResult
from starfish_sdk.client import StarfishClient
from starfish_sdk.crypto import Encryptor, create_encryptor
from starfish_sdk.types import ConflictError, ConflictResolver, DataSigner


class SyncManager:
    """High-level sync manager with pull, push, and automatic conflict resolution.

    Tracks the last known hash and checkpoint locally to support incremental sync
    and optimistic concurrency via hash-based conflict detection.
    """

    def __init__(
        self,
        client: StarfishClient,
        pull_path: str,
        push_path: str,
        *,
        on_conflict: ConflictResolver | None = None,
        max_retries: int = 3,
        encryption_secret: str | None = None,
        encryption_salt: str | None = None,
        encryption_info: str = "starfish-e2e",
        sign_data: DataSigner | None = None,
    ) -> None:
        self._client = client
        self._pull_path = pull_path
        self._push_path = push_path
        self._on_conflict = on_conflict or deep_merge
        self._max_retries = max_retries
        self._sign_data = sign_data
        if (encryption_secret is None) != (encryption_salt is None):
            raise ValueError("Both encryption_secret and encryption_salt must be provided together")
        self._encryptor: Encryptor | None = (
            create_encryptor(encryption_secret, encryption_salt, encryption_info)
            if encryption_secret is not None and encryption_salt is not None
            else None
        )

        self._last_hash: str | None = None
        self._last_checkpoint: int = 0
        self._local_data: dict[str, Any] = {}

    @property
    def data(self) -> dict[str, Any]:
        """Current local data snapshot."""
        return {**self._local_data}

    @property
    def hash(self) -> str | None:
        """Last known remote hash."""
        return self._last_hash

    @property
    def checkpoint(self) -> int:
        """Last checkpoint timestamp."""
        return self._last_checkpoint

    async def pull(self) -> PullResult:
        """Pull latest data from the server, using checkpoint for incremental sync."""
        result = await self._client.pull(self._pull_path, self._last_checkpoint)

        if self._encryptor is not None:
            decrypted = self._encryptor.decrypt(result.data)
            self._local_data = decrypted
            result.data = decrypted
        elif self._last_checkpoint > 0:
            self._local_data = deep_merge(self._local_data, result.data)
        else:
            self._local_data = result.data

        self._last_hash = result.hash
        self._last_checkpoint = result.timestamp
        return result

    async def push(self, data: dict[str, Any]) -> dict[str, Any]:
        """Push data with automatic conflict resolution. Returns dict with hash and timestamp."""
        attempt = 0
        pending_data = data

        while attempt <= self._max_retries:
            try:
                payload = (
                    self._encryptor.encrypt(pending_data)
                    if self._encryptor is not None
                    else pending_data
                )

                sig = (
                    await self._sign_data(stable_stringify(pending_data))
                    if self._sign_data is not None
                    else None
                )

                result = await self._client.push(
                    self._push_path, payload, self._last_hash, sig
                )
                self._last_hash = result.hash
                self._last_checkpoint = result.timestamp
                self._local_data = pending_data
                return {"hash": result.hash, "timestamp": result.timestamp}
            except ConflictError:
                if attempt >= self._max_retries:
                    raise
                remote = await self._client.pull(self._pull_path)
                self._last_hash = remote.hash
                self._last_checkpoint = remote.timestamp

                remote_data = (
                    self._encryptor.decrypt(remote.data)
                    if self._encryptor is not None
                    else remote.data
                )
                pending_data = self._on_conflict(pending_data, remote_data)
                delay = min(0.1 * (2 ** attempt), 2.0) + random.random() * 0.1
                await asyncio.sleep(delay)
                attempt += 1

        raise ConflictError()  # unreachable
