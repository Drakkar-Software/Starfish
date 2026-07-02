"""High-level sync manager with automatic conflict resolution."""

import asyncio
import base64
import random
from typing import Any, Protocol

from starfish_protocol.append_author import doc_author_canonical_input, verify_doc_author
from starfish_protocol.constants import (
    AUTHOR_PUBKEY_FIELD,
    AUTHOR_SIGNATURE_FIELD,
    PUSH_PATH_PREFIX,
)
from starfish_protocol.merge import deep_merge
from starfish_protocol.types import PullResult
from starfish_protocol.crypto import Encryptor
from starfish_sdk.append_log import AuthorVerifier
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


class DocAuthorError(Exception):
    """Raised when a pulled document's author signature fails verification
    (only when ``verify_author`` is enabled)."""

    def __init__(self) -> None:
        super().__init__("pulled document author verification failed")


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
        verify_author: bool | AuthorVerifier = False,
    ) -> None:
        self._client = client
        self._pull_path = pull_path
        self._push_path = push_path
        self._on_conflict = on_conflict or deep_merge
        self._max_retries = max_retries
        self._signer = signer
        self._encryptor: Encryptor | None = encryptor
        self._verify_author = verify_author
        # Reader derives the document key by stripping the ``/pull/`` action prefix —
        # it must match the key the writer signed over (push strips ``/push/``).
        self._document_key = pull_path.removeprefix("/pull/")

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

        # Verify authorship over the raw (pre-decryption) data before accepting it.
        self._verify_author_proof(result)

        if self._encryptor is not None:
            incoming = self._encryptor.decrypt(result.data)
            if self._aborted:
                raise AbortError()
        else:
            incoming = result.data

        # Honor the configured conflict resolver against the established baseline —
        # the same resolver the push-conflict path uses. The first pull (checkpoint 0)
        # takes the snapshot wholesale; an incremental pull merges local + remote so a
        # union/custom resolver does not drop local items on a shorter/stale snapshot.
        if self._last_checkpoint > 0:
            self._local_data = self._on_conflict(self._local_data, incoming)
        else:
            self._local_data = incoming
        result.data = self._local_data

        self._last_hash = result.hash
        self._last_checkpoint = result.timestamp
        return result

    def _verify_author_proof(self, result: PullResult) -> None:
        """Verify a pulled snapshot's author signature over its RAW
        (pre-decryption) ``data``, bound to the document key. Raises
        :class:`DocAuthorError` on any failure. No-op when ``verify_author``
        is disabled.

        TRUST MODEL: with ``none``-mode collections the server returns the
        document ``data`` alongside the author's Ed25519 ``author_pubkey`` /
        ``author_signature``. Leaving ``verify_author`` off means the client
        trusts the server not to forge content. Set it to ``True`` to require a
        valid signature for the self-declared key, or pass
        ``{"expected_author_pubkey": ...}`` to pin WHICH key must have signed.
        """
        v = self._verify_author
        if not v:
            return
        expected: str | None = None
        if isinstance(v, dict):
            expected = v.get("expected_author_pubkey")
        pub = result.author_pubkey
        sig = result.author_signature
        if not pub or not sig:
            raise DocAuthorError()
        # Public keys are hex (case-insensitive) — normalise before comparing.
        if expected is not None and pub.lower() != expected.lower():
            raise DocAuthorError()
        if not verify_doc_author(self._document_key, result.data, pub, sig):
            raise DocAuthorError()

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

                # v3 signer path: sign the document author proof over the
                # doc-author canonical input (domain-tagged, bound to documentKey)
                # and pass it as top-level body siblings of ``data`` (NOT inside
                # ``data``), where the server verifies it and stores the raw key.
                author: dict[str, str] | None = None
                if self._signer is not None:
                    ctx = await self._signer.get_signer()
                    if self._aborted:
                        raise AbortError()
                    dev_ed_pub_hex = ctx["dev_ed_pub_hex"]
                    sign_fn = ctx["sign"]
                    document_key = self._push_path.removeprefix(PUSH_PATH_PREFIX)
                    canonical = doc_author_canonical_input(document_key, sealed).encode("utf-8")
                    sig_bytes = await sign_fn(canonical)
                    if self._aborted:
                        raise AbortError()
                    author = {
                        AUTHOR_PUBKEY_FIELD: dev_ed_pub_hex,
                        AUTHOR_SIGNATURE_FIELD: base64.b64encode(sig_bytes).decode("ascii"),
                    }

                result = await self._client.push(
                    self._push_path, sealed, self._last_hash, author
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
