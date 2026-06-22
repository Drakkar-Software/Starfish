"""Wire token shapes for invite flows and resource requests.

Plain TypedDicts only — no logic.  Shared by members, nodes, and resource_requests.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict


# ── Join request (requester → owner) ─────────────────────────────────────────


class JoinRequest(TypedDict):
    """Sent by a prospective member to prove ownership of their keys."""

    edPub: str
    kemPub: str
    userId: str
    kemSig: str
    """Ed25519 signature of kemPub bytes by edPriv — proves kemPub ownership."""


# ── Space invite link token ───────────────────────────────────────────────────


class SpaceInviteLinkToken(TypedDict, total=False):
    """A space invite link token (v:1). Encodes the ephemeral credential in the URL fragment."""

    v: Literal[1]
    spaceId: str
    spaceName: str
    cap: Any
    key: str
    """The throwaway ephemeral subject's Ed25519 private key (hex)."""
    kemPriv: str
    """Ephemeral subject's X25519 KEM private key (hex) — needed to decrypt the space keyring."""
    kemPub: str
    """Ephemeral subject's X25519 KEM public key (hex) — identifies this token's keyring entry."""
    write: bool


# ── Node invite bundle ────────────────────────────────────────────────────────


NodeInviteKind = Literal["plaintext", "space-enc", "node-enc"]
"""
- ``'plaintext'``  — no encryption; content is readable without any keyring.
- ``'space-enc'``  — space-wide keyring (legacy enc invite).
- ``'node-enc'``   — per-node keyring (isolated E2EE ticket).
"""


class NodeInviteBundle(TypedDict, total=False):
    """Bundle sent by the owner to a node invitee."""

    spaceId: str
    nodeId: str
    nodeName: str
    kind: NodeInviteKind
    cap: Any
    nodeCap: Any
    streamCap: Any
    keyringCap: Any


# ── Node invite link token ────────────────────────────────────────────────────


class NodeInviteLinkToken(TypedDict, total=False):
    """A node invite link token (v:1)."""

    v: Literal[1]
    spaceId: str
    nodeId: str
    nodeName: str
    cap: Any
    streamCap: Any
    keyringCap: Any
    key: str
    """The ephemeral subject's Ed25519 private key (hex)."""
    write: bool


# ── Resource request / grant / reject ────────────────────────────────────────


class _ResourceRequester(TypedDict):
    userId: str
    edPub: str
    kemPub: str
    kemSig: str


class ResourceRequest(TypedDict, total=False):
    """Sealed inside an owner's inbox — 'please create a node in your space'."""

    v: Literal[1]
    kind: Literal["create-resource"]
    reqId: str
    """Stable id for dedup / idempotency."""
    spaceId: str
    nodeType: str
    title: str
    meta: dict[str, Any]
    message: str
    requester: _ResourceRequester


class ResourceGrant(TypedDict, total=False):
    """Sealed inside the requester's inbox — 'your request was accepted, here's your cap'."""

    v: Literal[1]
    kind: Literal["grant"]
    reqId: str
    spaceId: str
    nodeId: str
    bundle: str
    """Serialised ``NodeInviteBundle`` JSON — pass directly to ``accept_node_invite``."""


class ResourceReject(TypedDict, total=False):
    """Sealed inside the requester's inbox — 'your request was rejected'."""

    v: Literal[1]
    kind: Literal["reject"]
    reqId: str
    reason: str


# ── Owner-side stored node invite (for revocation) ────────────────────────────


class _CapNonceExp(TypedDict, total=False):
    nonce: str
    exp: int


class _StoredNodeInviteCaps(TypedDict, total=False):
    node: _CapNonceExp
    stream: _CapNonceExp
    keyring: _CapNonceExp


class StoredNodeInvite(TypedDict):
    """Stored by the owner after minting caps for a node invite, for later revocation."""

    edPub: str
    kemPub: str
    caps: _StoredNodeInviteCaps


__all__ = [
    "JoinRequest",
    "SpaceInviteLinkToken",
    "NodeInviteKind",
    "NodeInviteBundle",
    "NodeInviteLinkToken",
    "ResourceRequest",
    "ResourceGrant",
    "ResourceReject",
    "StoredNodeInvite",
]
