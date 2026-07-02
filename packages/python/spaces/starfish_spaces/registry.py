"""Space and access registries (plaintext metadata documents).

A user's spaces live at ``user/{userId}/_spaces``; each space's access record
(owner/members + shared name/image) at ``spaces/{spaceId}/_access``.  All writes
use the CAS retry helper from :mod:`starfish_spaces.cas_retry`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Optional

from starfish_protocol.random import random_id
from starfish_sdk.types import StarfishHttpError

from starfish_spaces.cas_retry import run_cas
from starfish_spaces.object_index import seed_space_object_index

if TYPE_CHECKING:
    from starfish_sdk import StarfishClient
    from starfish_spaces.config import CapMap, PubAccessMap, SealedBlob, Space
    from starfish_spaces.session import Session


# ── Module-level meta-listener set ───────────────────────────────────────────

_space_meta_listeners: set[Callable[[str, dict[str, Any]], None]] = set()


def on_space_meta(fn: Callable[[str, dict[str, Any]], None]) -> Callable[[], None]:
    """Register a listener for ``{name, short, image?}`` meta broadcasts.

    Returns a zero-argument callable that removes the listener.
    """
    _space_meta_listeners.add(fn)
    return lambda: _space_meta_listeners.discard(fn)


def broadcast_space_meta(space_id: str, meta: dict[str, Any]) -> None:
    """Fire all registered listeners with ``space_id`` and the update dict."""
    for fn in list(_space_meta_listeners):
        try:
            fn(space_id, meta)
        except Exception:
            pass


# ── Constants ─────────────────────────────────────────────────────────────────

_CORE_SPACES_KEYS = frozenset({"spaces", "caps", "pubAccess", "v", "hash"})
_SPACE_FALLBACK_SUFFIX = 6


# ── Space builder ─────────────────────────────────────────────────────────────


def build_space(
    space_id: str,
    name: str,
    overrides: Optional[dict[str, Any]] = None,
) -> "Space":
    """Build a :class:`Space` dict with computed ``short`` monogram."""
    from starfish_spaces.config import Space  # lazy to avoid circular

    trimmed = name.strip() or f"space-{space_id[-_SPACE_FALLBACK_SUFFIX:]}"
    base: dict[str, Any] = {
        "id": space_id,
        "name": trimmed,
        "members": 1,
    }
    if overrides:
        base.update(overrides)
    return Space(**{k: base.get(k) for k in Space.__dataclass_fields__})  # type: ignore[attr-defined]


# ── SpacesDoc helpers ─────────────────────────────────────────────────────────


class SpacesDoc:
    """In-memory model of the ``_spaces`` doc (spaces list + cap/link maps + extra)."""

    __slots__ = ("spaces", "caps", "pub_access", "extra", "hash")

    def __init__(
        self,
        spaces: list[Any],
        caps: "CapMap",
        pub_access: "PubAccessMap",
        extra: dict[str, Any],
        hash: Optional[str],
    ) -> None:
        self.spaces = spaces
        self.caps = caps
        self.pub_access = pub_access
        self.extra = extra
        self.hash = hash


def _collect_extra(data: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not data or not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if k not in _CORE_SPACES_KEYS}


def _coerce_spaces_doc(
    data: Optional[dict[str, Any]],
    hash: Optional[str],
) -> SpacesDoc:
    if not isinstance(data, dict):
        return SpacesDoc([], {}, {}, {}, hash)
    return SpacesDoc(
        spaces=list(data.get("spaces", [])) if isinstance(data.get("spaces"), list) else [],
        caps=dict(data.get("caps", {})) if isinstance(data.get("caps"), dict) else {},
        pub_access=dict(data.get("pubAccess", {})) if isinstance(data.get("pubAccess"), dict) else {},
        extra=_collect_extra(data),
        hash=hash,
    )


def _to_payload(doc: SpacesDoc) -> dict[str, Any]:
    """Spread extra FIRST so core fields always take precedence."""
    return {
        **doc.extra,
        "spaces": doc.spaces,
        "caps": doc.caps,
        "pubAccess": doc.pub_access,
    }


async def _pull_spaces_doc(client: "StarfishClient", session: "Session") -> SpacesDoc:
    try:
        res = await client.pull(session.layout.spaces_pull(session.user_id))
        data = res.data if hasattr(res, "data") else res
        hash_ = res.hash if hasattr(res, "hash") else None
        return _coerce_spaces_doc(data if isinstance(data, dict) else None, hash_)
    except StarfishHttpError as exc:
        if exc.status == 404:
            return SpacesDoc([], {}, {}, {}, None)
        raise


# ── Public readers/writers ────────────────────────────────────────────────────


async def read_spaces(client: "StarfishClient", session: "Session") -> SpacesDoc:
    """Pull the ``_spaces`` doc; returns an empty doc on any error."""
    try:
        return await _pull_spaces_doc(client, session)
    except Exception:
        return SpacesDoc([], {}, {}, {}, None)


async def update_spaces_doc(
    client: "StarfishClient",
    session: "Session",
    mutator: Callable[[dict[str, Any]], Optional[dict[str, Any]]],
) -> None:
    """CAS read-modify-write the ``_spaces`` doc.

    ``mutator`` receives ``{spaces, caps, pubAccess}`` and must return either a
    modified dict or ``None`` to skip the write.
    """
    async def attempt() -> None:
        doc = await _pull_spaces_doc(client, session)
        cur = {"spaces": doc.spaces, "caps": doc.caps, "pubAccess": doc.pub_access}
        next_ = mutator(cur)
        if next_ is None or next_ is cur:
            return
        merged = SpacesDoc(
            spaces=next_.get("spaces", doc.spaces),
            caps=next_.get("caps", doc.caps),
            pub_access=next_.get("pubAccess", doc.pub_access),
            extra=doc.extra,
            hash=doc.hash,
        )
        payload = {"v": 1, **_to_payload(merged)}
        await client.push(session.layout.spaces_push(session.user_id), payload, doc.hash)

    await run_cas(attempt)


async def update_spaces_extra_field(
    client: "StarfishClient",
    session: "Session",
    key: str,
    mutator: Callable[[Optional[Any]], Optional[Any]],
) -> None:
    """CAS update one app-specific ``extra`` field in the ``_spaces`` doc."""
    async def attempt() -> None:
        doc = await _pull_spaces_doc(client, session)
        next_val = mutator(doc.extra.get(key))
        if next_val is None:
            return
        payload = {**_to_payload(doc), key: next_val, "v": 1}
        await client.push(session.layout.spaces_push(session.user_id), payload, doc.hash)

    await run_cas(attempt)


async def write_spaces(
    client: "StarfishClient",
    session: "Session",
    spaces: list[Any],
) -> None:
    """Overwrite the ``spaces`` list (preserving caps + pubAccess)."""
    await update_spaces_doc(client, session, lambda cur: {
        "spaces": spaces, "caps": cur["caps"], "pubAccess": cur["pubAccess"]
    })


async def reorder_spaces(
    client: "StarfishClient",
    session: "Session",
    order: list[str],
) -> None:
    """Re-order the spaces list to match ``order`` (unknown ids appended)."""
    def mutator(cur: dict[str, Any]) -> Optional[dict[str, Any]]:
        by_id = {s["id"]: s for s in cur["spaces"] if isinstance(s, dict) and "id" in s}
        next_list: list[Any] = []
        seen = set()
        for id_ in order:
            if id_ in by_id and id_ not in seen:
                next_list.append(by_id[id_])
                seen.add(id_)
        # Append remaining
        for s in cur["spaces"]:
            if isinstance(s, dict) and s.get("id") not in seen:
                next_list.append(s)
        if next_list == cur["spaces"]:
            return None
        return {"spaces": next_list, "caps": cur["caps"], "pubAccess": cur["pubAccess"]}

    await update_spaces_doc(client, session, mutator)


async def move_space(
    client: "StarfishClient",
    session: "Session",
    space_id: str,
    to_index: int,
) -> None:
    """Move one space to an absolute index in the list (clamped)."""
    def mutator(cur: dict[str, Any]) -> Optional[dict[str, Any]]:
        spaces = cur["spaces"]
        from_ = next((i for i, s in enumerate(spaces) if isinstance(s, dict) and s.get("id") == space_id), -1)
        if from_ == -1:
            return None
        lst = list(spaces)
        moved = lst.pop(from_)
        idx = max(0, min(to_index, len(lst)))
        lst.insert(idx, moved)
        if lst == spaces:
            return None
        return {"spaces": lst, "caps": cur["caps"], "pubAccess": cur["pubAccess"]}

    await update_spaces_doc(client, session, mutator)


# ── SpaceEntry / _access doc ──────────────────────────────────────────────────


class SpaceEntry:
    """Model for the ``_access`` doc of a space."""

    __slots__ = ("owner", "members", "name", "image", "hash")

    def __init__(
        self,
        owner: Optional[str],
        members: list[str],
        name: Optional[str],
        image: Optional[str],
        hash: Optional[str],
    ) -> None:
        self.owner = owner
        self.members = members
        self.name = name
        self.image = image
        self.hash = hash


def _parse_space_access(data: Any, hash_: Optional[str]) -> "SpaceEntry":
    """Parse a raw ``_access`` doc body + hash into a :class:`SpaceEntry`."""
    if not isinstance(data, dict):
        return SpaceEntry(None, [], None, None, None)
    members = [m for m in data.get("members", []) if isinstance(m, str)]
    return SpaceEntry(
        owner=data.get("owner") if isinstance(data.get("owner"), str) else None,
        members=members,
        name=data.get("name") if isinstance(data.get("name"), str) else None,
        image=data.get("image") if isinstance(data.get("image"), str) else None,
        hash=hash_,
    )


async def read_space_access(
    client: "StarfishClient",
    space_id: str,
    session: "Session",
) -> SpaceEntry:
    """Pull the ``_access`` doc for ``space_id``; returns empty entry on 404."""
    try:
        res = await client.pull(session.layout.space_access_pull(space_id))
        data = res.data if hasattr(res, "data") else {}
        hash_ = res.hash if hasattr(res, "hash") else None
    except StarfishHttpError as exc:
        if exc.status == 404:
            return SpaceEntry(None, [], None, None, None)
        raise

    return _parse_space_access(data, hash_)


async def read_space_access_batch(
    session: "Session",
    space_ids: list[str],
) -> dict[str, "SpaceEntry"]:
    """Batch-read the ``_access`` doc for many spaces in a single round-trip.

    Requires the server to be configured with :func:`spaces_collections` and
    :func:`create_spaces_role_enricher` (``allow_tofu=False``, the default),
    and the caller to use the account-scoped shared client
    (``session.spaces_registry_client``) whose cap scope covers ``spaces/**``.

    Returns a ``dict[space_id, SpaceEntry]`` containing ONLY the spaces the caller
    is authorised to read.  Spaces where the server returns ``{"error": ...}``
    (e.g. caller is not a member, or the space does not exist) are silently omitted.
    """
    if not space_ids:
        return {}
    entries = await session.spaces_registry_client.batch_pull_many(
        "spaceaccess",
        [{"spaceId": sid} for sid in space_ids],
    )
    result: dict[str, SpaceEntry] = {}
    for i, space_id in enumerate(space_ids):
        if i >= len(entries):
            break
        entry = entries[i]
        if not isinstance(entry, dict) or entry.get("error"):
            continue
        result[space_id] = _parse_space_access(entry.get("data"), entry.get("hash"))
    return result


async def write_space_access(
    client: "StarfishClient",
    space_id: str,
    owner: str,
    members: list[str],
    hash: Optional[str],
    session: "Session",
    meta: Optional[dict[str, Any]] = None,
) -> None:
    """Write the ``_access`` doc for ``space_id``."""
    payload: dict[str, Any] = {"v": 1, "owner": owner, "members": members}
    name = (meta or {}).get("name", "")
    image = (meta or {}).get("image", "")
    if name and isinstance(name, str) and name.strip():
        payload["name"] = name.strip()
    if image and isinstance(image, str):
        payload["image"] = image
    await client.push(session.layout.space_access_push(space_id), payload, hash)


async def _update_space_access(
    client: "StarfishClient",
    space_id: str,
    session: "Session",
    mutator: Callable[["SpaceEntry"], Optional[dict[str, Any]]],
) -> None:
    """CAS read-modify-write the ``_access`` doc for ``space_id``.

    ``mutator`` receives the freshly-read :class:`SpaceEntry` and returns either
    ``{"owner", "members"}`` or ``None`` to skip the write.  Re-reads the current
    hash + members on every retried attempt, so a stale-hash 409 on the first
    pass is retried against the newest state (mirrors the TS ``updateSpaceAccess``).
    """
    async def attempt() -> None:
        cur = await read_space_access(client, space_id, session)
        nxt = mutator(cur)
        if nxt is None:
            return
        await write_space_access(
            client, space_id, nxt["owner"], nxt["members"], cur.hash, session,
            {"name": cur.name, "image": cur.image},
        )

    await run_cas(attempt)


async def add_space_member(
    client: "StarfishClient",
    space_id: str,
    owner_user_id: str,
    member_user_id: str,
    session: "Session",
) -> None:
    """Add ``member_user_id`` to the space roster (idempotent, CAS-retried)."""
    def mutator(cur: "SpaceEntry") -> Optional[dict[str, Any]]:
        owner = cur.owner or owner_user_id
        if member_user_id == owner or member_user_id in cur.members:
            return None
        return {"owner": owner, "members": [*cur.members, member_user_id]}

    await _update_space_access(client, space_id, session, mutator)


async def remove_space_member(
    client: "StarfishClient",
    space_id: str,
    member_user_id: str,
    session: "Session",
) -> None:
    """Remove ``member_user_id`` from the space roster (idempotent, CAS-retried)."""
    def mutator(cur: "SpaceEntry") -> Optional[dict[str, Any]]:
        if member_user_id not in cur.members:
            return None
        return {"owner": cur.owner or member_user_id,
                "members": [m for m in cur.members if m != member_user_id]}

    await _update_space_access(client, space_id, session, mutator)


# ── Registry join/remove helpers ──────────────────────────────────────────────


async def remove_joined_space(
    client: "StarfishClient",
    session: "Session",
    space_id: str,
) -> None:
    """Drop a space from the identity's own list + forget its credentials."""
    def mutator(cur: dict[str, Any]) -> Optional[dict[str, Any]]:
        if not any(s.get("id") == space_id for s in cur["spaces"] if isinstance(s, dict)):
            return None  # already absent
        caps = {k: v for k, v in cur["caps"].items() if k != space_id}
        pub_access = {k: v for k, v in cur["pubAccess"].items() if k != space_id}
        return {"spaces": [s for s in cur["spaces"] if not (isinstance(s, dict) and s.get("id") == space_id)],
                "caps": caps, "pubAccess": pub_access}

    await update_spaces_doc(client, session, mutator)


def _add_space_with_updates(
    client: "StarfishClient",
    session: "Session",
    space: Any,
    updates: Optional[dict[str, Any]] = None,
) -> Any:
    space_id = space.id if hasattr(space, "id") else space.get("id") if isinstance(space, dict) else ""
    space_dict = {"id": space_id, "name": getattr(space, "name", ""), "members": getattr(space, "members", 1)}

    def mutator(cur: dict[str, Any]) -> Optional[dict[str, Any]]:
        exists = any(s.get("id") == space_id for s in cur["spaces"] if isinstance(s, dict))
        if exists and not updates:
            return None
        caps = dict(cur["caps"])
        pub_access = dict(cur["pubAccess"])
        if updates:
            if updates.get("caps"):
                caps.update(updates["caps"])
            if updates.get("pubAccess"):
                pub_access.update(updates["pubAccess"])
        return {
            "spaces": cur["spaces"] if exists else [*cur["spaces"], space_dict],
            "caps": caps,
            "pubAccess": pub_access,
        }

    return update_spaces_doc(client, session, mutator)


def add_joined_space(client: "StarfishClient", session: "Session", space: Any) -> Any:
    """Append a space to the joined list (dup-guarded)."""
    return _add_space_with_updates(client, session, space)


def add_joined_space_with_cap(
    client: "StarfishClient", session: "Session", space: Any, cap_json: str
) -> Any:
    """Append a space to the joined list + store its cap JSON."""
    space_id = space.id if hasattr(space, "id") else space.get("id", "")
    return _add_space_with_updates(client, session, space, {"caps": {space_id: cap_json}})


def add_joined_space_with_link_access(
    client: "StarfishClient", session: "Session", space: Any, sealed: "SealedBlob"
) -> Any:
    """Append a space to the joined list + store its sealed link-access blob."""
    space_id = space.id if hasattr(space, "id") else space.get("id", "")
    sealed_dict = {"v": sealed.v, "ct": sealed.ct, "wks": sealed.wks} if hasattr(sealed, "v") else dict(sealed)
    return _add_space_with_updates(client, session, space, {"pubAccess": {space_id: sealed_dict}})


# ── Space creation ────────────────────────────────────────────────────────────


async def create_space(session: "Session", name: str) -> Any:
    """Create a new space owned by the identity, seeding its object index.

    Returns:
        The new :class:`Space` object.
    """
    client = session.account_client
    doc = await read_spaces(client, session)
    trimmed = name.strip() or "New Space"
    space_id = f"{session.space_id_prefix}{random_id()}"
    space = build_space(space_id, trimmed)
    await write_space_access(
        client, space_id, session.user_id, [], None, session, {"name": trimmed}
    )
    await seed_space_object_index(session.content_client, session, space_id)
    await write_spaces(client, session, [*doc.spaces, space])
    return space


# ── Meta reconciliation ───────────────────────────────────────────────────────


async def reconcile_space_meta(
    client: "StarfishClient",
    session: "Session",
    space_id: str,
    shared: dict[str, Any],
    known_spaces: Optional[list[Any]] = None,
) -> None:
    """Merge shared ``{name, image}`` into the local spaces list (idempotent)."""
    shared_name = shared.get("name", "")
    if isinstance(shared_name, str):
        shared_name = shared_name.strip() or None
    else:
        shared_name = None
    shared_image = shared.get("image") if isinstance(shared.get("image"), str) else None

    if shared_name is None and shared_image is None:
        return

    doc = await read_spaces(client, session)
    cur_space = next((s for s in doc.spaces if isinstance(s, dict) and s.get("id") == space_id), None)
    if not cur_space:
        return

    name = shared_name or cur_space.get("name", "")
    image = shared_image or cur_space.get("image")
    if name == cur_space.get("name") and image == cur_space.get("image"):
        return

    next_spaces = [
        ({**s, "name": name, **({"image": image} if image else {})} if s.get("id") == space_id else s)
        for s in doc.spaces
    ]
    await write_spaces(client, session, next_spaces)
    short = (name or "")[:2].upper()
    meta_update = {"name": name, "short": short}
    if image:
        meta_update["image"] = image
    broadcast_space_meta(space_id, meta_update)


__all__ = [
    "SpacesDoc",
    "SpaceEntry",
    "on_space_meta",
    "broadcast_space_meta",
    "build_space",
    "read_spaces",
    "update_spaces_doc",
    "update_spaces_extra_field",
    "write_spaces",
    "reorder_spaces",
    "move_space",
    "read_space_access",
    "write_space_access",
    "add_space_member",
    "remove_space_member",
    "remove_joined_space",
    "add_joined_space",
    "add_joined_space_with_cap",
    "add_joined_space_with_link_access",
    "create_space",
    "reconcile_space_meta",
]
