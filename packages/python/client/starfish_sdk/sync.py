"""High-level sync manager with automatic conflict resolution."""

import asyncio
import base64
import random
from typing import Any, Protocol

from starfish_protocol.hash import stable_stringify
from starfish_protocol.merge import deep_merge
from starfish_protocol.types import PullResult
from starfish_protocol.crypto import Encryptor
from starfish_sdk.client import StarfishClient
from starfish_sdk.types import ConflictError, ConflictResolver


class SyncSigner(Protocol):
    """v3.0 author-signature plumbing for :class:`SyncManager`.

    ``get_signer()`` returns ``{"dev_ed_pub_hex": <str>, "sign": async fn}``.
    The ``sign`` function receives the canonical signing-input bytes and
    must return the raw 64-byte Ed25519 signature.

    Typical implementations wrap the same Ed25519 private key used by
    :class:`CapProvider` so that ``cap.sub == dev_ed_pub_hex``.
    """

    async def get_signer(self) -> dict[str, Any]:
        """Return ``{"dev_ed_pub_hex": <str>, "sign": <async (bytes) -> bytes>}``."""
        ...


class AbortError(Exception):
    """Raised when a SyncManager operation is cancelled via abort()."""

    def __init__(self) -> None:
        super().__init__("SyncManager was aborted")


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
        encryptor: Encryptor | None = None,
        signer: SyncSigner | None = None,
    ) -> None:
        self._client = client
        self._pull_path = pull_path
        self._push_path = push_path
        self._on_conflict = on_conflict or deep_merge
        self._max_retries = max_retries
        self._signer = signer
        self._encryptor: Encryptor | None = encryptor

        self._last_hash: str | None = None
        self._last_checkpoint: int = 0
        self._local_data: dict[str, Any] = {}
        self._aborted: bool = False

    def abort(self) -> None:
        """Cancel any in-flight push or pull. Future operations immediately raise AbortError."""
        self._aborted = True

    @property
    def is_aborted(self) -> bool:
        """True if abort() has been called."""
        return self._aborted

    @property
    def data(self) -> dict[str, Any]:
        """Current local data snapshot."""
        return {**self._local_data}

    @property
    def hash(self) -> str | None:
        """Last known remote hash."""
        return self._last_hash

    def set_hash(self, hash: str | None) -> None:
        """Set the last-known server hash. Used by persistence layers to restore state across restarts."""
        self._last_hash = hash

    @property
    def checkpoint(self) -> int:
        """Last checkpoint timestamp."""
        return self._last_checkpoint

    async def pull(self) -> PullResult:
        """Pull latest data from the server, using checkpoint for incremental sync."""
        if self._aborted:
            raise AbortError()
        result = await self._client.pull(self._pull_path, self._last_checkpoint)
        if self._aborted:
            raise AbortError()

        if self._encryptor is not None:
            decrypted = self._encryptor.decrypt(result.data)
            if self._aborted:
                raise AbortError()
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
        if self._aborted:
            raise AbortError()
        attempt = 0
        pending_data = data

        while attempt <= self._max_retries:
            try:
                sealed = (
                    self._encryptor.encrypt(pending_data)
                    if self._encryptor is not None
                    else pending_data
                )
                if self._aborted:
                    raise AbortError()

                # v3 signer path: sign over stable_stringify(payload-without-author-fields)
                # and attach authorPubkey + authorSignature INSIDE the sealed
                # payload (data field).
                payload: dict[str, Any] = sealed
                if self._signer is not None:
                    ctx = await self._signer.get_signer()
                    if self._aborted:
                        raise AbortError()
                    dev_ed_pub_hex = ctx["dev_ed_pub_hex"]
                    sign_fn = ctx["sign"]
                    canonical = stable_stringify(sealed).encode("utf-8")
                    sig_bytes = await sign_fn(canonical)
                    if self._aborted:
                        raise AbortError()
                    payload = {
                        **sealed,
                        "authorPubkey": dev_ed_pub_hex,
                        "authorSignature": base64.b64encode(sig_bytes).decode("ascii"),
                    }

                result = await self._client.push(
                    self._push_path, payload, self._last_hash
                )
                if self._aborted:
                    raise AbortError()
                self._last_hash = result.hash
                self._last_checkpoint = result.timestamp
                self._local_data = pending_data
                return {"hash": result.hash, "timestamp": result.timestamp}
            except AbortError:
                raise
            except ConflictError:
                if attempt >= self._max_retries:
                    raise
                remote = await self._client.pull(self._pull_path)
                if self._aborted:
                    raise AbortError()
                self._last_hash = remote.hash
                self._last_checkpoint = remote.timestamp

                remote_data = (
                    self._encryptor.decrypt(remote.data)
                    if self._encryptor is not None
                    else remote.data
                )
                if self._aborted:
                    raise AbortError()
                pending_data = self._on_conflict(pending_data, remote_data)
                delay = min(0.1 * (2 ** attempt), 2.0) + random.random() * 0.1
                await asyncio.sleep(delay)
                attempt += 1

        raise ConflictError()  # unreachable
