"""Configuration seam and central domain-type home.

:class:`SpaceLayout` is a ``Protocol`` (structural) that produces every
collection path and cap-scope from ``(space_id, node_id, user_id)``.  An app
injects its concrete implementation via :func:`configure_spaces`; the package
ships :data:`default_space_layout` as a ready-to-use default.

:class:`SpacesConfig` bundles the runtime knobs (layout, userId derivation, id
prefixes, AAD/KV namespaces) that an app may override.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Optional, Protocol, runtime_checkable


# ── Scalar domain types ───────────────────────────────────────────────────────

ID = str
"""A space or node identifier string."""

CapMap = dict[str, str]
"""Map of ``{userId: serializedCap}``."""

MuteValue = bool | int
"""``True`` to mute indefinitely, or a Unix-ms expiry timestamp."""

ObjectType = str
"""Application-defined node type string (e.g. ``'room'``, ``'page'``)."""

ObjectContentKind = str
"""``'merge'`` | ``'append'`` | ``'none'``."""

NodeAccess = str
"""``'public'`` | ``'space'`` | ``'invite'``."""


# ── Wire types ────────────────────────────────────────────────────────────────


@dataclass
class SealedBlob:
    """An AES-256-GCM sealed envelope.

    Wire format: ``ct = hex(iv[12] ‖ AES-GCM-ciphertext)``.  Note: distinct
    from starfish-keyring's base64 ``ct`` format.
    """

    entry: dict[str, Any]
    """A ``WrappedKeyEntry``-shaped dict produced by the keyring layer."""

    ct: str
    """Hex of ``iv[12] ‖ AES-GCM ciphertext``."""

    v: Optional[int] = None
    """When ``1``, the blob was sealed with an AAD context binding and
    ``unseal_from_self`` / ``unseal_from_recipient`` require the same AAD."""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"entry": self.entry, "ct": self.ct}
        if self.v is not None:
            out["v"] = self.v
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SealedBlob":
        return cls(
            entry=dict(data["entry"]),
            ct=data["ct"],
            v=data.get("v"),
        )


class PubAccessMap(dict):
    """``{userId: SealedBlob-dict}`` — public-access links for invite-join."""


@dataclass
class ObjectNode:
    """A node in the space's object tree."""

    id: str
    type: str
    parent_id: Optional[str]
    order: float
    title: str
    updated_at: int
    emoji: Optional[str] = None
    archived: Optional[bool] = None
    content_kind: Optional[str] = None
    access: Optional[str] = None
    enc: Optional[bool] = None
    meta: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "parentId": self.parent_id,
            "order": self.order,
            "title": self.title,
            "updatedAt": self.updated_at,
        }
        if self.emoji is not None:
            out["emoji"] = self.emoji
        if self.archived is not None:
            out["archived"] = self.archived
        if self.content_kind is not None:
            out["contentKind"] = self.content_kind
        if self.access is not None:
            out["access"] = self.access
        if self.enc is not None:
            out["enc"] = self.enc
        if self.meta is not None:
            out["meta"] = self.meta
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ObjectNode":
        return cls(
            id=data["id"],
            type=data["type"],
            parent_id=data.get("parentId"),
            order=float(data.get("order", 0)),
            title=data.get("title", ""),
            updated_at=int(data.get("updatedAt", 0)),
            emoji=data.get("emoji"),
            archived=data.get("archived"),
            content_kind=data.get("contentKind"),
            access=data.get("access"),
            enc=data.get("enc"),
            meta=data.get("meta"),
        )


@dataclass
class ObjectsIndex:
    """The space's unified object index document (``v:2``)."""

    objects: list[dict[str, Any]]
    updated_at: int
    v: int = 2

    def to_dict(self) -> dict[str, Any]:
        return {"v": self.v, "objects": self.objects, "updatedAt": self.updated_at}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ObjectsIndex":
        return cls(
            objects=list(data.get("objects", [])),
            updated_at=int(data.get("updatedAt", 0)),
            v=int(data.get("v", 2)),
        )


@dataclass
class Space:
    """A space entry in the user's ``_spaces`` registry doc."""

    id: str
    name: str
    members: dict[str, Any] = field(default_factory=dict)


# ── SpaceLayout protocol ──────────────────────────────────────────────────────


@runtime_checkable
class SpaceLayout(Protocol):
    """Produces every collection path and cap-scope for the spaces domain.

    All path methods return strings with a ``/pull/`` or ``/push/`` prefix
    so they can be passed directly to ``StarfishClient.pull()`` / ``.push()``.
    """

    # ── Registry paths ────────────────────────────────────────────────────────
    def spaces_pull(self, user_id: str) -> str: ...
    def spaces_push(self, user_id: str) -> str: ...
    def space_access_pull(self, space_id: str) -> str: ...
    def space_access_push(self, space_id: str) -> str: ...

    # ── Object index paths ────────────────────────────────────────────────────
    def obj_index_pull(self, space_id: str) -> str: ...
    def obj_index_push(self, space_id: str) -> str: ...

    # ── Space-wide keyring paths ──────────────────────────────────────────────
    def keyring_name(self, space_id: str) -> str: ...
    def keyring_pull(self, space_id: str) -> str: ...
    def keyring_push(self, space_id: str) -> str: ...

    # ── Per-node keyring paths ────────────────────────────────────────────────
    def node_keyring_name(self, space_id: str, node_id: str) -> str: ...
    def node_keyring_pull(self, space_id: str, node_id: str) -> str: ...
    def node_keyring_push(self, space_id: str, node_id: str) -> str: ...

    # ── Inbox paths ───────────────────────────────────────────────────────────
    def inbox_pull(self, identity: str, shard: Optional[str] = None) -> str: ...
    def inbox_push(self, identity: str, shard: Optional[str] = None) -> str: ...

    # ── Profile paths ─────────────────────────────────────────────────────────
    def profile_pull(self, user_id: str) -> str: ...
    def profile_push(self, user_id: str) -> str: ...

    # ── Object directory ──────────────────────────────────────────────────────
    def object_dir_pull(self, shard: Optional[str] = None) -> str: ...

    # ── Cap scopes ────────────────────────────────────────────────────────────
    def owner_scope(self) -> dict[str, Any]: ...
    def space_owner_scope(self, space_id: str) -> dict[str, Any]: ...
    def space_member_scope(self, space_id: str, can_write: bool) -> dict[str, Any]: ...
    def node_member_scope(self, space_id: str, node_id: str, can_write: bool) -> dict[str, Any]: ...
    def node_stream_scope(self, space_id: str, node_id: str, can_write: bool) -> dict[str, Any]: ...
    def node_keyring_scope(self, space_id: str, node_id: str) -> dict[str, Any]: ...
    def account_scope(self, user_id: str) -> dict[str, Any]: ...
    def linked_device_scope(self, user_id: str) -> dict[str, Any]: ...


# ── KvAdapter protocol ────────────────────────────────────────────────────────


@runtime_checkable
class KvAdapter(Protocol):
    """Async key-value storage adapter for local access-store persistence."""

    async def get_item(self, key: str) -> Optional[str]: ...
    async def set_item(self, key: str, value: str) -> None: ...
    async def remove_item(self, key: str) -> None: ...


# ── SpacesConfig ──────────────────────────────────────────────────────────────


@dataclass
class SpacesConfig:
    """Runtime configuration knobs for the spaces domain.

    All fields are optional; :func:`get_spaces_config` returns the app-level
    config merged with defaults (see :mod:`starfish_spaces.layout`).
    """

    layout: Optional[SpaceLayout] = None
    """Custom path/scope layout.  Defaults to :data:`default_space_layout`."""

    user_id_from_ed_pub: Optional[Callable[[str], Coroutine[Any, Any, str]]] = None
    """Async ``(edPubHex) -> userId`` hook.  Defaults to ``default_user_id_from_ed_pub``."""

    space_id_prefix: Optional[str] = None
    """Default ``"sp-"``."""

    node_id_prefix: Optional[str] = None
    """Default ``"obj-"``."""

    inbox_aad_namespace: Optional[str] = None
    """Default ``"starfish:inbox:v1"``."""

    kv_key_prefix: Optional[str] = None
    """Default ``"starfish.spaceaccess."``."""

    kv_adapter: Optional[KvAdapter] = None


# ── Module-level config registry ──────────────────────────────────────────────

_config: SpacesConfig = SpacesConfig()


def configure_spaces(opts: SpacesConfig) -> None:
    """Set the module-level :class:`SpacesConfig` for this process.

    Call once at app startup, before any spaces API is invoked.
    """
    global _config
    _config = opts


def get_spaces_config() -> SpacesConfig:
    """Return the currently installed :class:`SpacesConfig`."""
    return _config


__all__ = [
    "ID",
    "CapMap",
    "MuteValue",
    "ObjectType",
    "ObjectContentKind",
    "NodeAccess",
    "SealedBlob",
    "PubAccessMap",
    "ObjectNode",
    "ObjectsIndex",
    "Space",
    "SpaceLayout",
    "KvAdapter",
    "SpacesConfig",
    "configure_spaces",
    "get_spaces_config",
]
