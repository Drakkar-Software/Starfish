"""KV-backed PullCache factory.

Mirrors ``packages/ts/client/src/kv-cache.ts``.

Adapts any :class:`KvStore` (async ``get``/``set``) into a :class:`PullCache`
that the ``StarfishClient`` can use as its offline read-through cache.

The cache stores a JSON envelope around each payload::

    {"payload": "<raw>", "_cached_at": <epoch_ms>}

so that optional max-age expiry can be checked on read without a separate
metadata key. Reading a plain-string entry (no ``_cached_at``) treats it as
fresh for backward-compatibility.

All ``get``/``set`` errors are swallowed — a failing KV store degrades to
"no cache" without crashing the caller.
"""

from __future__ import annotations

import json
import time
from typing import Optional, Protocol, runtime_checkable


# ── KvStore protocol ──────────────────────────────────────────────────────────

@runtime_checkable
class KvStore(Protocol):
    """Minimal async KV store interface."""

    async def get(self, key: str) -> Optional[str]:
        """Return the stored string value, or ``None`` if the key is absent."""
        ...

    async def set(self, key: str, value: str) -> None:
        """Persist *value* under *key*."""
        ...


# ── PullCache protocol ────────────────────────────────────────────────────────

@runtime_checkable
class PullCache(Protocol):
    """Async read/write cache for pull results (raw JSON strings)."""

    async def read(self, key: str) -> Optional[str]:
        """Return the cached raw payload string, or ``None`` on a miss/expiry."""
        ...

    async def write(self, key: str, data: str) -> None:
        """Persist *data* under *key*."""
        ...


# ── KvPullCache ───────────────────────────────────────────────────────────────

class KvPullCache:
    """PullCache backed by an async KV store.

    Stores JSON-serialised pull results in an envelope
    ``{"payload": "<raw>", "_cached_at": <epoch_ms>}``
    with optional max-age expiry.
    """

    def __init__(
        self,
        kv: KvStore,
        prefix: str = "starfish.pullcache.",
        max_age_ms: Optional[int] = None,
    ) -> None:
        self._kv = kv
        self._prefix = prefix
        self._max_age_ms = max_age_ms

    async def read(self, key: str) -> Optional[str]:
        """Return the cached payload, or ``None`` on miss / expiry / error."""
        try:
            raw = await self._kv.get(self._prefix + key)
            if raw is None:
                return None

            # Try the envelope format first; fall back to plain-string for
            # backward-compatibility with caches written before this library.
            payload: str
            cached_at: Optional[int] = None
            try:
                envelope = json.loads(raw)
                if isinstance(envelope, dict) and isinstance(envelope.get("payload"), str):
                    payload = envelope["payload"]
                    cached_at = envelope.get("_cached_at")
                else:
                    payload = raw
            except (json.JSONDecodeError, ValueError):
                payload = raw

            if self._max_age_ms is not None and cached_at is not None:
                age_ms = int(time.time() * 1000) - cached_at
                if age_ms > self._max_age_ms:
                    return None

            return payload
        except Exception:
            return None

    async def write(self, key: str, data: str) -> None:
        """Persist *data* under the prefixed *key*. Errors are silently swallowed."""
        try:
            cached_at = int(time.time() * 1000)
            envelope = json.dumps({"payload": data, "_cached_at": cached_at})
            await self._kv.set(self._prefix + key, envelope)
        except Exception:
            pass


# ── factory ───────────────────────────────────────────────────────────────────

def create_kv_pull_cache(
    kv: KvStore,
    prefix: str = "starfish.pullcache.",
    max_age_ms: Optional[int] = None,
) -> KvPullCache:
    """Wrap *kv* in a :class:`KvPullCache`.

    Args:
        kv:         Any async KV store (``get``/``set``).
        prefix:     Key prefix for cache entries. Change to avoid collisions
                    when the KV store is shared with other data.
        max_age_ms: Maximum age in milliseconds. Entries older than this are
                    treated as misses. ``None`` (default) means never expire.
    """
    return KvPullCache(kv, prefix=prefix, max_age_ms=max_age_ms)
