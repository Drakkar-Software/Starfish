"""``HttpReplicaChannel`` — the original HTTP-pull-into-local-``ObjectStore``
sync mechanics, moved verbatim out of the old ``ReplicaManager._do_sync`` /
``proxy_push``. Mirrors the TS package's ``http-channel.ts``.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from starfish_protocol.merge import deep_merge
from starfish_server.protocol.push import push
from starfish_server.router.helpers import deep_sanitize
from starfish_server.protocol.types import PushSuccess
from starfish_server.storage.base import AbstractObjectStore

from starfish_replica.config import RemoteCollection, RemoteConfig, WriteMode
from starfish_replica.channel import ReplicaCallContext

logger = logging.getLogger(__name__)

__all__ = ["HttpReplicaChannel"]


class HttpReplicaChannel:
    """Replicates one :class:`RemoteCollection` from a primary starfish server
    into a local :class:`AbstractObjectStore`."""

    def __init__(
        self,
        store: AbstractObjectStore,
        col: RemoteCollection,
        client: httpx.AsyncClient,
    ) -> None:
        self.name = col.name
        self.remote: RemoteConfig = col.remote
        self._store = store
        self._col = col
        self._client = client
        self._last_hash: str | None = None

    async def sync(self, ctx: ReplicaCallContext) -> None:
        remote = self.remote
        col = self._col

        if remote.write_mode == WriteMode.PUSH_ONLY:
            return

        document_key = col.storage_path

        primary_url = f"{remote.url.rstrip('/')}{remote.pull_path}"
        resp = await self._client.get(
            primary_url,
            headers={"Accept": "application/json", **remote.headers},
        )
        resp.raise_for_status()
        pulled: dict[str, Any] = resp.json()

        primary_hash: str = pulled.get("hash", "")
        primary_data: dict[str, Any] = pulled.get("data", {})

        if not primary_hash:
            return

        if self._last_hash == primary_hash:
            return

        raw_local = await self._store.get_string(document_key)
        current_local_hash: str = ""
        current_local_data: dict[str, Any] = {}
        if raw_local:
            try:
                local_doc = json.loads(raw_local)
                current_local_hash = local_doc.get("hash", "")
                current_local_data = local_doc.get("data", {})
            except json.JSONDecodeError as exc:
                logger.error(
                    "[ReplicaManager] Corrupt local document at %r — treating as empty: %s",
                    document_key, exc,
                )
                # current_local_hash stays "" — push with baseHash="" will overwrite

        if current_local_hash == primary_hash:
            self._last_hash = primary_hash
            return

        if remote.write_mode == WriteMode.BIDIRECTIONAL and current_local_data:
            data_to_write = deep_merge(current_local_data, primary_data)
        else:
            data_to_write = primary_data

        # Strip prototype-pollution keys before writing primary data into the
        # local store. The bidirectional merge drops them via deep_merge, but the
        # pull-only / push-through path writes the primary's ``data`` verbatim and
        # must not trust it — a compromised primary could otherwise plant a
        # ``__proto__`` / ``__class__`` payload.
        sanitized = deep_sanitize(data_to_write)

        # Use current_local_hash directly ("" works for both "no document" and
        # "corrupt document"): push() treats base_hash="" the same as no hash when
        # the stored current_hash is also "". Must NOT coerce "" → None — push()
        # rejects base_hash=None when a (corrupt) doc is present, which would leave
        # a corrupt local doc permanently unrecoverable (sync would raise
        # "Concurrent write" forever). A valid local doc still yields its real
        # hash, so genuine concurrent-write detection is preserved.
        base_hash = current_local_hash
        result = await push(self._store, document_key, sanitized, base_hash)

        if not isinstance(result, PushSuccess):
            raise RuntimeError(
                f"[ReplicaManager] Concurrent write on {self.name!r} — will retry"
            )

        self._last_hash = result.hash
        logger.debug("[ReplicaManager] Synced %r (hash=%s)", self.name, result.hash)

    async def proxy_push(
        self,
        raw_body: bytes | str,
        *,
        on_success: Any = None,
    ) -> tuple[int, Any]:
        """Forward a client push to the primary (write_mode ``push_through``).

        Returns ``(status, body)`` to relay to the client. On success, calls
        ``on_success()`` (if given) so the caller can trigger a background
        sync — this channel does not know about the scheduler that owns it.
        """
        remote = self.remote
        primary_url = f"{remote.url.rstrip('/')}{remote.push_path}"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **remote.headers,
        }

        try:
            resp = await self._client.post(primary_url, content=raw_body, headers=headers)
        except httpx.HTTPError as exc:
            logger.error("Failed to reach primary for %r: %s", self.name, exc)
            return 502, {"error": "Failed to reach primary"}

        if resp.status_code == 409:
            return 409, {"error": "hash_mismatch"}
        if not resp.is_success:
            return resp.status_code, {"error": f"Primary returned {resp.status_code}"}

        body = resp.json()

        # Validate the primary's response shape before relaying it to our client.
        # A successful push returns ``{ hash, timestamp }``; refuse to forward an
        # arbitrary/garbage body a compromised or misbehaving primary might send.
        if not isinstance(body, dict) or not isinstance(body.get("hash"), str):
            logger.error("Primary returned an unexpected push response shape for %r", self.name)
            return 502, {"error": "Primary returned an unexpected response"}

        if on_success is not None:
            on_success()

        return resp.status_code, body
