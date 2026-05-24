"""In-memory nonce cache for replay protection of v3 signed requests.

Mirror of ``packages/ts/server/src/auth/nonce-cache.ts``. See that file
for the protocol-level rationale.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Protocol


# Default window is 2× the request clock-skew (5 min) — see
# ``create_in_memory_nonce_cache`` for why this MUST be ≥ 2× skew.
_DEFAULT_WINDOW_MS = 10 * 60 * 1000
_DEFAULT_MAX_ENTRIES = 100_000
_DEFAULT_PER_SIGNER_LIMIT = 4_096


class NonceCache(Protocol):
    """Pluggable contract for a nonce-cache backend."""

    def check_and_remember(
        self, signer_ed_pub_hex: str, nonce_base64: str, now_ms: int
    ) -> bool:
        """Return ``True`` iff the nonce is fresh; ``False`` on replay.

        A ``True`` result marks the nonce as seen with expiry
        ``now_ms + window_ms``.
        """
        ...


class _InMemoryNonceCache:
    """In-memory implementation with a per-signer sub-cap.

    A **live** (non-expired) nonce is never evicted — doing so would re-open a
    replay slot. Expired entries are reclaimed on each call; if a cap is reached
    with all entries still live, the new nonce is rejected (fail closed). Every
    entry uses the same ``window_ms``, so insertion order == expiry order.
    """

    def __init__(
        self, window_ms: int, max_entries: int, per_signer_limit: int
    ) -> None:
        self._window_ms = window_ms
        self._max_entries = max_entries
        self._per_signer_limit = per_signer_limit
        self._seen: "OrderedDict[str, int]" = OrderedDict()
        # Per-signer ordered map nonce → exp.
        self._by_signer: dict[str, "OrderedDict[str, int]"] = {}

    def _drop(self, signer: str, nonce: str) -> None:
        self._seen.pop(f"{signer}|{nonce}", None)
        sub = self._by_signer.get(signer)
        if sub is not None:
            sub.pop(nonce, None)
            if not sub:
                del self._by_signer[signer]

    def check_and_remember(
        self, signer_ed_pub_hex: str, nonce_base64: str, now_ms: int
    ) -> bool:
        key = f"{signer_ed_pub_hex}|{nonce_base64}"
        existing = self._seen.get(key)
        if existing is not None:
            if existing >= now_ms:
                # Still within window (expiry == now still counts as live) →
                # replay.
                return False
            # Expired — drop so it can be re-inserted as fresh below.
            self._drop(signer_ed_pub_hex, nonce_base64)

        # Reclaim ALL expired entries (oldest-first; stop at the first live one,
        # since insertion order == expiry order). This is what frees capacity —
        # never the eviction of a live nonce. An entry whose expiry equals
        # ``now_ms`` is still live, matching the replay check above.
        to_delete: list[str] = []
        for k, exp in self._seen.items():
            if exp >= now_ms:
                break
            to_delete.append(k)
        for k in to_delete:
            sep = k.find("|")
            if sep > 0:
                self._drop(k[:sep], k[sep + 1:])
            else:
                self._seen.pop(k, None)

        # Fail closed when a cap is hit with all-live entries: reject rather
        # than evict a live nonce (which would let it be replayed).
        sub_cache = self._by_signer.get(signer_ed_pub_hex)
        if sub_cache is not None and len(sub_cache) >= self._per_signer_limit:
            return False
        if len(self._seen) >= self._max_entries:
            return False

        expiry = now_ms + self._window_ms
        self._seen[key] = expiry
        if sub_cache is None:
            sub_cache = OrderedDict()
            self._by_signer[signer_ed_pub_hex] = sub_cache
        sub_cache[nonce_base64] = expiry
        return True


def create_in_memory_nonce_cache(
    *,
    window_ms: int = _DEFAULT_WINDOW_MS,
    max_entries: int = _DEFAULT_MAX_ENTRIES,
    per_signer_limit: int = _DEFAULT_PER_SIGNER_LIMIT,
) -> NonceCache:
    """Build an in-memory nonce cache with a per-signer sub-cap.

    A **live** (non-expired) nonce is never evicted — doing so would re-open a
    replay slot. Expired entries are reclaimed on each call; if a cap is hit
    with all entries still live, the new nonce is rejected (fail closed).

    :param window_ms: Acceptance window in milliseconds (default 10 min). MUST
        be ≥ 2× the request clock-skew (5 min) the server accepts: a request is
        accepted in ``[ts − skew, ts + skew]``, so a replay must remain catchable
        in the cache for the full ``2 × skew`` span before the skew gate rejects
        it. A shorter window re-opens a replay slot.
    :param max_entries: Global cap (default 100 000).
    :param per_signer_limit: Per-signer cap on live nonces (default 4 096).
        Enforced fail-closed; size for your peak per-signer request rate over
        ``window_ms`` or use a shared store for multi-instance deployments.
    """
    return _InMemoryNonceCache(window_ms, max_entries, per_signer_limit)


__all__ = ["NonceCache", "create_in_memory_nonce_cache"]
