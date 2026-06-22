"""Space and node access resolver with local caching.

Resolves which StarfishClient + Encryptor pair to use for a given node access
request.  The resolution order (6 tiers) mirrors the TypeScript implementation:

1. Per-node link access entry from the local store.
2. Per-node member cap entry from the local store.
3. Space-level link access entry from the local store.
4. Space-level member cap entry from the local store.
5. Owner self-mint (if ``session.keys.edPub == session.owner_ed_pub``).
6. Non-owner fallback — raises :class:`SpaceAccessError`.

Resolved handles are cached in two module-level dicts:
- ``_cache``: keyed ``"{userId}:{spaceId}:{nodeId}"`` → :class:`NodeAccessHandle`.
- ``_space_encryptor_cache``: keyed ``"{userId}:{spaceId}"`` → encryptor.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from starfish_spaces.client import (
    build_encryptor,
    make_space_client,
    open_encryptor,
)
from starfish_spaces.space_access_error import SpaceAccessError
from starfish_spaces.space_access_store import (
    SpaceAccessEntry,
    get_node_access_entry,
    get_node_keyring_access_entry,
    get_node_stream_access_entry,
    get_space_access_entry,
    link_access_from_store,
    member_caps_from_store,
)

if TYPE_CHECKING:
    from starfish_sdk import StarfishClient
    from starfish_spaces.session import Session

# ── Module-level caches ───────────────────────────────────────────────────────

_cache: dict[str, "NodeAccessHandle"] = {}
_space_encryptor_cache: dict[str, Any] = {}


def clear_node_access_cache() -> None:
    """Clear both module-level caches."""
    _cache.clear()
    _space_encryptor_cache.clear()


# ── Types ─────────────────────────────────────────────────────────────────────


@dataclass
class NodeAccessHandle:
    """Resolved access handle for a single node."""

    client: "StarfishClient"
    """An authenticated client with the right cap for this node."""

    encryptor: Optional[Any] = None
    """A :class:`KeyringEncryptor` when the node is E2EE-encrypted, else ``None``."""

    is_owner_open: bool = False
    """``True`` when the handle was resolved via owner self-mint."""


# ── Resolution helpers ────────────────────────────────────────────────────────


async def _decrypt_keys_for(
    entry: SpaceAccessEntry,
    session: "Session",
) -> tuple[Optional[str], Optional[str]]:
    """Decrypt the ephemeral keys from a link-access entry.

    Returns ``(ed_priv_hex, kem_priv_hex)`` or ``(None, None)`` on failure.
    """
    if entry.get("kind") != "link":
        return None, None
    return entry.get("key"), entry.get("kemPriv")


async def get_space_client(
    session: "Session",
    space_id: str,
) -> "StarfishClient":
    """Return an authenticated client for the space's main content collection.

    Uses the session's ``content_client`` (owner) or the stored cap entry.

    Raises:
        SpaceAccessError: when no credential is found for this space.
    """
    from starfish_spaces.client import ClientOpts

    # Try stored member cap.
    entries = member_caps_from_store(space_id)
    if entries:
        entry = entries[0]
        cap = entry.get("cap")
        ed_priv = session.keys["edPriv"]
        opts: ClientOpts = {"baseUrl": session.base_url, "namespace": session.namespace}  # type: ignore[misc]
        return make_space_client(cap, ed_priv, opts)

    # Try link access.
    link = link_access_from_store(space_id)
    if link:
        cap = link.get("cap")
        ed_priv = link.get("key") or session.keys["edPriv"]
        opts = {"baseUrl": session.base_url, "namespace": session.namespace}  # type: ignore[misc]
        return make_space_client(cap, ed_priv, opts)

    # Owner fallback.
    if session.keys["edPub"] == session.owner_ed_pub:
        return session.content_client

    raise SpaceAccessError(space_id)


async def get_node_stream_client(
    session: "Session",
    space_id: str,
    node_id: str,
) -> "StarfishClient":
    """Return an authenticated client for the node's stream (``objinvlog``) collection."""
    from starfish_spaces.client import ClientOpts

    stream_entry = get_node_stream_access_entry(space_id, node_id)
    if stream_entry:
        cap = stream_entry.get("cap")
        ed_priv = stream_entry.get("key") or session.keys["edPriv"]
        opts: ClientOpts = {"baseUrl": session.base_url, "namespace": session.namespace}  # type: ignore[misc]
        return make_space_client(cap, ed_priv, opts)

    # Fall back to the space client.
    return await get_space_client(session, space_id)


async def get_node_access(
    session: "Session",
    space_id: str,
    node_id: str,
) -> NodeAccessHandle:
    """Resolve the :class:`NodeAccessHandle` for ``(space_id, node_id)``.

    Result is cached in ``_cache`` after first resolution.

    Raises:
        SpaceAccessError: when no credential can be found or derived.
    """
    cache_key = f"{session.user_id}:{space_id}:{node_id}"
    if cache_key in _cache:
        return _cache[cache_key]

    handle = await _resolve_node_access(session, space_id, node_id)
    _cache[cache_key] = handle
    return handle


async def _resolve_node_access(
    session: "Session",
    space_id: str,
    node_id: str,
) -> NodeAccessHandle:
    from starfish_spaces.client import ClientOpts
    from starfish_spaces.node_keyring import build_node_encryptor

    opts: ClientOpts = {"baseUrl": session.base_url, "namespace": session.namespace}  # type: ignore[misc]

    # Tier 1 — per-node link access.
    node_link = get_node_access_entry(space_id, node_id)
    if node_link and node_link.get("kind") == "link":
        cap = node_link.get("cap")
        ed_priv = node_link.get("key") or session.keys["edPriv"]
        kem_priv = node_link.get("kemPriv")
        client = make_space_client(cap, ed_priv, opts)
        encryptor = None
        keyring_entry = get_node_keyring_access_entry(space_id, node_id)
        if keyring_entry and kem_priv:
            keyring_cap = keyring_entry.get("cap")
            keyring_client = make_space_client(keyring_cap, ed_priv, opts)
            encryptor = await build_encryptor(
                keyring_client,
                session.layout.node_keyring_name(space_id, node_id),
                kem_priv,
                space_id=space_id,
                node_id=node_id,
            )
        return NodeAccessHandle(client=client, encryptor=encryptor)

    # Tier 2 — per-node member cap.
    node_member = get_node_access_entry(space_id, node_id)
    if node_member and node_member.get("kind") == "member":
        cap = node_member.get("cap")
        client = make_space_client(cap, session.keys["edPriv"], opts)
        keyring_entry = get_node_keyring_access_entry(space_id, node_id)
        encryptor = None
        if keyring_entry:
            keyring_cap = keyring_entry.get("cap")
            keyring_client = make_space_client(keyring_cap, session.keys["edPriv"], opts)
            encryptor = await build_encryptor(
                keyring_client,
                session.layout.node_keyring_name(space_id, node_id),
                session.keys["kemPriv"],
                space_id=space_id,
                node_id=node_id,
            )
        return NodeAccessHandle(client=client, encryptor=encryptor)

    # Tier 3 — space-level link access.
    space_link = link_access_from_store(space_id)
    if space_link:
        cap = space_link.get("cap")
        ed_priv = space_link.get("key") or session.keys["edPriv"]
        kem_priv = space_link.get("kemPriv")
        client = make_space_client(cap, ed_priv, opts)
        encryptor = None
        if kem_priv:
            enc_key = f"{session.user_id}:{space_id}"
            if enc_key in _space_encryptor_cache:
                encryptor = _space_encryptor_cache[enc_key]
            else:
                encryptor = await build_encryptor(
                    client,
                    session.layout.keyring_name(space_id),
                    kem_priv,
                    space_id=space_id,
                )
                if encryptor:
                    _space_encryptor_cache[enc_key] = encryptor
        return NodeAccessHandle(client=client, encryptor=encryptor)

    # Tier 4 — space-level member cap.
    space_member_entries = member_caps_from_store(space_id)
    if space_member_entries:
        cap = space_member_entries[0].get("cap")
        client = make_space_client(cap, session.keys["edPriv"], opts)
        encryptor = None
        enc_key = f"{session.user_id}:{space_id}"
        if enc_key in _space_encryptor_cache:
            encryptor = _space_encryptor_cache[enc_key]
        else:
            from starfish_spaces.node_keyring import owner_trusted_adders
            trusted = owner_trusted_adders(session)
            encryptor = await build_encryptor(
                client,
                session.layout.keyring_name(space_id),
                session.keys["kemPriv"],
                trusted_adders=trusted,
                space_id=space_id,
            )
            if encryptor:
                _space_encryptor_cache[enc_key] = encryptor
        return NodeAccessHandle(client=client, encryptor=encryptor)

    # Tier 5 — owner self-mint.
    if session.keys["edPub"] == session.owner_ed_pub:
        from starfish_spaces.node_keyring import owner_trusted_adders
        trusted = owner_trusted_adders(session)
        client = session.content_client
        encryptor = await build_node_encryptor(client, session, space_id, node_id, session.layout)
        if encryptor is None:
            # Try space-level keyring.
            encryptor = await build_encryptor(
                client,
                session.layout.keyring_name(space_id),
                session.keys["kemPriv"],
                trusted_adders=trusted,
                space_id=space_id,
            )
        return NodeAccessHandle(client=client, encryptor=encryptor, is_owner_open=True)

    # Tier 6 — no credential found.
    raise SpaceAccessError(space_id, node_id)


async def build_node_access(
    session: "Session",
    space_id: str,
    node_id: str,
) -> NodeAccessHandle:
    """Like :func:`get_node_access` but never raises — returns a best-effort handle."""
    try:
        return await get_node_access(session, space_id, node_id)
    except SpaceAccessError:
        return NodeAccessHandle(client=session.content_client)


__all__ = [
    "NodeAccessHandle",
    "get_space_client",
    "get_node_stream_client",
    "get_node_access",
    "build_node_access",
    "clear_node_access_cache",
]
