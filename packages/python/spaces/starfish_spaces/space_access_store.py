"""Unified local space-access store.

Two entry kinds:
- **member** — a capability certificate ``{kind: "member", cap: ...}`` received from an invite.
- **link**   — a link-access payload ``{kind: "link", cap: ..., key: str, kemPriv?: str, kemPub?: str, write: bool}``.

Two tiers for persistence:
1. **In-memory cache** (``_cache``) — keyed ``"{userId}:{spaceId}"`` for space-level entries,
   ``"{userId}:{spaceId}:{nodeId}"`` for node content, ``"…:{nodeId}:stream"`` for stream,
   ``"…:{nodeId}:keyring"`` for per-node keyring.
2. **KV store** (``_kv``) — optional async KV adapter for persistence across restarts.
   The KV key is ``"{_kv_key_prefix}{userId}:{spaceId}"``.

The module operates on a single active user at a time (``_active_key`` holds the
current userId).  Call :func:`configure_space_access_store` at session-build time
and :func:`clear_space_access_store` on session teardown.
"""

from __future__ import annotations

import json
from typing import Any, Optional, TypedDict

from starfish_spaces.config import KvAdapter

# ── Entry types ───────────────────────────────────────────────────────────────


class LinkAccessPayload(TypedDict, total=False):
    """Cap + ephemeral keys stored for link-join access."""

    cap: Any
    key: str
    """Ephemeral subject's Ed25519 private key (hex)."""
    kemPriv: str
    kemPub: str
    write: bool


class _MemberEntry(TypedDict):
    kind: str  # "member"
    cap: Any


class _LinkEntry(TypedDict, total=False):
    kind: str  # "link"
    cap: Any
    key: str
    kemPriv: str
    kemPub: str
    write: bool


SpaceAccessEntry = Any  # union of member/link dicts
SpaceAccessMap = dict[str, SpaceAccessEntry]

# ── Module-level singletons ───────────────────────────────────────────────────

_cache: dict[str, SpaceAccessEntry] = {}
_active_key: Optional[str] = None
_kv: Optional[KvAdapter] = None
_kv_key_prefix: str = "starfish.spaceaccess."


def configure_space_access_store(
    user_id: str,
    kv: Optional[KvAdapter] = None,
    kv_key_prefix: str = "starfish.spaceaccess.",
) -> None:
    """Configure the store for a new session.

    Call at session build time before any access-store operations.
    """
    global _active_key, _kv, _kv_key_prefix
    _active_key = user_id
    _kv = kv
    _kv_key_prefix = kv_key_prefix


def clear_space_access_store() -> None:
    """Clear the in-memory cache and reset active-user state."""
    global _cache, _active_key
    _cache = {}
    _active_key = None


# ── Key helpers ───────────────────────────────────────────────────────────────


def _key_for(space_id: str) -> str:
    return f"{_active_key}:{space_id}"


def _node_key(space_id: str, node_id: str, suffix: str = "") -> str:
    base = f"{_active_key}:{space_id}:{node_id}"
    return f"{base}:{suffix}" if suffix else base


def _kv_key(space_id: str) -> str:
    return f"{_kv_key_prefix}{_active_key}:{space_id}"


# ── KV persistence ────────────────────────────────────────────────────────────


async def _persist(space_id: str) -> None:
    """Write the current cache entries for ``space_id`` to KV (if adapter set)."""
    if _kv is None:
        return
    # Collect all entries for this space.
    prefix = f"{_active_key}:{space_id}"
    subset = {k: v for k, v in _cache.items() if k == prefix or k.startswith(prefix + ":")}
    await _kv.set_item(_kv_key(space_id), json.dumps(subset))


async def _load_from_kv(space_id: str) -> Optional[dict[str, SpaceAccessEntry]]:
    if _kv is None:
        return None
    raw = await _kv.get_item(_kv_key(space_id))
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


# ── Hydration ─────────────────────────────────────────────────────────────────


async def hydrate_space_access_store(
    space_id: str,
    server_entries: Optional[SpaceAccessMap] = None,
) -> None:
    """Load access entries for ``space_id`` from KV (then server entries win).

    1. Try to load from KV first (fast path for offline / cold start).
    2. Merge ``server_entries`` on top (server wins over KV).
    3. Store the merged result in the in-memory cache and persist back to KV.

    Args:
        space_id:       The space to hydrate.
        server_entries: Authoritative entries from the server ``_spaces`` doc
            (``{userId: {kind, cap, ...}}``). Each key is a ``userId``; the value
            is a member or link entry.  Pass ``None`` to skip server merge.
    """
    global _cache

    # Step 1 — KV
    kv_data = await _load_from_kv(space_id)
    if kv_data:
        _cache.update(kv_data)

    # Step 2 — server wins
    if server_entries:
        for uid, entry in server_entries.items():
            cache_key = f"{_active_key}:{space_id}:{uid}" if uid != _active_key else _key_for(space_id)
            # Server entries are space-level member entries for each userId.
            # Store under the main space key for the active user.
            if uid == _active_key:
                _cache[_key_for(space_id)] = entry
            else:
                _cache[f"{_active_key}:{space_id}:{uid}"] = entry

    # Step 3 — persist merged state
    await _persist(space_id)


# ── Space-level accessors ─────────────────────────────────────────────────────


def get_space_access_entry(space_id: str) -> Optional[SpaceAccessEntry]:
    """Get the access entry for ``space_id`` in the active user's store."""
    return _cache.get(_key_for(space_id))


def save_space_access_entry(space_id: str, entry: SpaceAccessEntry) -> None:
    """Save an access entry for ``space_id`` (in-memory only; call :func:`persist_space_access` to flush)."""
    _cache[_key_for(space_id)] = entry


def remove_space_access_entry(space_id: str) -> None:
    """Remove the space-level access entry for ``space_id``."""
    _cache.pop(_key_for(space_id), None)


# ── Node-tier accessors factory ───────────────────────────────────────────────


def _node_entry_api(suffix: str = ""):
    """Return (get, save, remove) accessors for node entries with the given suffix."""

    def get(space_id: str, node_id: str) -> Optional[SpaceAccessEntry]:
        return _cache.get(_node_key(space_id, node_id, suffix))

    def save(space_id: str, node_id: str, entry: SpaceAccessEntry) -> None:
        _cache[_node_key(space_id, node_id, suffix)] = entry

    def remove(space_id: str, node_id: str) -> None:
        _cache.pop(_node_key(space_id, node_id, suffix), None)

    return get, save, remove


get_node_access_entry, save_node_access_entry, _remove_node = _node_entry_api("")
get_node_stream_access_entry, save_node_stream_access_entry, remove_node_stream_access_entry = (
    _node_entry_api("stream")
)
get_node_keyring_access_entry, save_node_keyring_access_entry, remove_node_keyring_access_entry = (
    _node_entry_api("keyring")
)


def remove_node_access_entry(space_id: str, node_id: str) -> None:
    """Remove all three node-tier entries (content + stream + keyring) for ``node_id``."""
    _remove_node(space_id, node_id)
    remove_node_stream_access_entry(space_id, node_id)
    remove_node_keyring_access_entry(space_id, node_id)


# ── Bulk read helpers ─────────────────────────────────────────────────────────


def local_space_access_entries() -> list[tuple[str, SpaceAccessEntry]]:
    """Return all cached ``(space_id, entry)`` pairs for space-level keys."""
    results = []
    prefix = f"{_active_key}:"
    for k, v in _cache.items():
        # Space-level keys have exactly ONE colon after the user prefix, not two.
        stripped = k[len(prefix):] if k.startswith(prefix) else None
        if stripped and ":" not in stripped:
            results.append((stripped, v))
    return results


def member_caps_from_store(space_id: str) -> list[SpaceAccessEntry]:
    """Return all ``kind=member`` entries for ``space_id``."""
    entry = get_space_access_entry(space_id)
    if entry and entry.get("kind") == "member":
        return [entry]
    return []


def link_access_from_store(space_id: str) -> Optional[LinkAccessPayload]:
    """Return the ``kind=link`` entry for ``space_id``, or ``None``."""
    entry = get_space_access_entry(space_id)
    if entry and entry.get("kind") == "link":
        return entry  # type: ignore[return-value]
    return None


# ── Persistence helpers ───────────────────────────────────────────────────────


async def persist_space_access(space_id: str) -> None:
    """Flush the in-memory entries for ``space_id`` to the KV adapter."""
    await _persist(space_id)


async def clear_persisted_space_access(space_id: str) -> None:
    """Remove the KV entry for ``space_id``."""
    if _kv is not None:
        await _kv.remove_item(_kv_key(space_id))


__all__ = [
    "LinkAccessPayload",
    "SpaceAccessEntry",
    "SpaceAccessMap",
    "configure_space_access_store",
    "clear_space_access_store",
    "hydrate_space_access_store",
    "get_space_access_entry",
    "save_space_access_entry",
    "remove_space_access_entry",
    "get_node_access_entry",
    "save_node_access_entry",
    "remove_node_access_entry",
    "get_node_stream_access_entry",
    "save_node_stream_access_entry",
    "remove_node_stream_access_entry",
    "get_node_keyring_access_entry",
    "save_node_keyring_access_entry",
    "remove_node_keyring_access_entry",
    "local_space_access_entries",
    "member_caps_from_store",
    "link_access_from_store",
    "persist_space_access",
    "clear_persisted_space_access",
]
