"""Per-node creation, access management, and invite flows.

Nodes are the atomic content units of a space. Each node carries two independent axes:

- ``access``: ``'public' | 'space' | 'invite'`` — who may reach the node.
- ``enc``: ``bool`` — whether content is E2EE under the space-wide keyring.

Invalid combo: ``access:'public' + enc:True`` is rejected outright.

Encryption uses ONE space keyring (at ``spaces/{spaceId}/_keyring``). Any space
member holding the keyring can decrypt ALL ``enc`` nodes in the space.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Optional, TypedDict

from starfish_protocol.encoding import decode_link_fragment, encode_link_fragment
from starfish_protocol.random import random_id

from starfish_spaces.account_seal import seal_to_self
from starfish_spaces.client import (
    ensure_space_keyring_recipient,
    owner_ensure_space_keyring,
)
from starfish_spaces.invite_helpers import (
    CapSubject,
    assert_cap_for_me,
    assert_cap_not_expired,
    cap_nonce,
    ephemeral_subject_async,
    evict_keyring_member,
    mint_cap,
    parse_join_request,
)
from starfish_spaces.keyed_store import create_composed_store
from starfish_spaces.layout import RECIPIENT_LABEL_LEN
from starfish_spaces.node_keyring import (
    add_node_keyring_recipient,
    ensure_node_keyring_recipient,
    owner_ensure_node_keyring,
)
from starfish_spaces.object_index import update_object_index
from starfish_spaces.objects import NewObjectInput, add_object
from starfish_spaces.registry import add_space_member, build_space
from starfish_spaces.space_access_store import (
    save_node_access_entry,
    save_node_keyring_access_entry,
    save_node_stream_access_entry,
    save_space_access_entry,
)
from starfish_spaces.token_types import NodeInviteBundle, NodeInviteLinkToken, StoredNodeInvite

if TYPE_CHECKING:
    from starfish_spaces.config import ObjectNode
    from starfish_spaces.session import Session


# ── Utilities ─────────────────────────────────────────────────────────────────


def _recipient_for(sub_kem: str, user_id: str) -> dict[str, str]:
    return {"subKem": sub_kem, "userId": user_id, "label": user_id[:RECIPIENT_LABEL_LEN]}


# ── Node invite store (nonces for revocation) ─────────────────────────────────


_node_invite_store = create_composed_store(
    compose_key=lambda space_id, node_id, user_id: f"{space_id}:{node_id}:{user_id}"
)
_ni_raw = _node_invite_store.store


def save_node_invite_entry(space_id: str, node_id: str, user_id: str, entry: StoredNodeInvite) -> None:
    """Record caps for an isolated node invite (owner side)."""
    _node_invite_store.for_(space_id, node_id, user_id).set(entry)


def get_node_invite_entry(space_id: str, node_id: str, user_id: str) -> Optional[StoredNodeInvite]:
    """Retrieve the stored invite entry for a user on a node, or ``None``."""
    return _node_invite_store.for_(space_id, node_id, user_id).get()


def clear_node_invite_store() -> None:
    """Clear all stored invite entries."""
    _ni_raw.clear_all()


def serialize_node_invite_store() -> str:
    return _ni_raw.serialize()


def hydrate_node_invite_store(raw: str) -> None:
    _ni_raw.hydrate(raw)


# ── CreateNodeInput ───────────────────────────────────────────────────────────


class CreateNodeInput(TypedDict, total=False):
    """Input for :func:`create_node`."""

    type: str
    title: str
    emoji: Optional[str]
    parentId: Optional[str]
    access: Optional[str]
    enc: Optional[bool]
    meta: Optional[dict[str, Any]]


# ── createNode ────────────────────────────────────────────────────────────────


async def create_node(
    session: "Session",
    space_id: str,
    inp: CreateNodeInput,
) -> "ObjectNode":
    """Create a new node in a space's object index.

    Raises:
        ValueError: if ``access='public'`` and ``enc=True``.

    Returns:
        The created :class:`ObjectNode`.
    """
    from starfish_spaces.config import ObjectNode

    access = inp.get("access") or "space"
    enc = bool(inp.get("enc"))
    if access == "public" and enc:
        raise ValueError("public+enc is not a valid combination.")

    node_id = f"{session.node_id_prefix}{random_id()}"

    if enc:
        await owner_ensure_space_keyring(session.content_client, session.keys, space_id, session.layout)  # type: ignore[arg-type]

    created: list[ObjectNode] = []

    def mutator(nodes: list[ObjectNode]) -> Optional[list[ObjectNode]]:
        new_input = NewObjectInput(
            id=node_id,
            type=inp.get("type") or "page",
            title=inp.get("title") or "",
            parent_id=inp.get("parentId"),
            emoji=inp.get("emoji"),
            meta=inp.get("meta"),
            access=access if access != "space" else None,  # type: ignore[arg-type]
            enc=True if enc else None,
        )
        updated, node = add_object(nodes, new_input)
        created.append(node)
        return updated

    await update_object_index(session.content_client, session, space_id, mutator)

    if not created:
        raise RuntimeError("create_node: index update did not produce a node")

    # NOTE: the creator does NOT get a minted "member" stream cap for their own
    # node here. A `kind:"member"` cap asserts `subUserId != issUserId`
    # (starfish-sharing's assert_member_cap_shape) -- it exists to grant access
    # to someone ELSE, not to the issuer's own identity. The owner already has
    # implicit access to nodes in their own space via the account/owner cap
    # scope; minting a self-targeted member cap here always fails that shape
    # check and would make every create_node() call throw against a real server.

    return created[0]


# ── setNodeAccess ─────────────────────────────────────────────────────────────


async def set_node_access(
    session: "Session",
    space_id: str,
    node_id: str,
    patch: dict[str, Any],
) -> None:
    """Patch the ``access``/``enc`` axes of a node in the index.

    Raises:
        ValueError: if the result would be the invalid ``public+enc`` combo.
    """
    from starfish_spaces.config import ObjectNode

    if patch.get("access") == "public" and patch.get("enc"):
        raise ValueError("public+enc is not valid.")

    if patch.get("enc"):
        await owner_ensure_space_keyring(session.content_client, session.keys, space_id, session.layout)  # type: ignore[arg-type]

    def mutator(nodes: list[ObjectNode]) -> Optional[list[ObjectNode]]:
        import time
        now = int(time.time() * 1000)
        idx = next((i for i, n in enumerate(nodes) if n.id == node_id), -1)
        if idx < 0:
            return None

        cur = nodes[idx]
        cur_d = cur.to_dict()
        next_d = {**cur_d, "updatedAt": now}

        if "access" in patch:
            if patch["access"] == "space":
                next_d.pop("access", None)
            else:
                next_d["access"] = patch["access"]

        if "enc" in patch:
            if not patch["enc"]:
                next_d.pop("enc", None)
            else:
                next_d["enc"] = True

        if next_d.get("access") == "public" and next_d.get("enc"):
            raise ValueError("public+enc is not valid.")

        if next_d.get("access") == cur_d.get("access") and bool(next_d.get("enc")) == bool(cur_d.get("enc")):
            return None  # unchanged

        updated = ObjectNode.from_dict(next_d)
        return [updated if i == idx else n for i, n in enumerate(nodes)]

    await update_object_index(session.content_client, session, space_id, mutator)


# ── inviteToNode ──────────────────────────────────────────────────────────────


async def invite_to_node(
    session: "Session",
    space_id: str,
    node_id: str,
    request_json: str,
    node: dict[str, Any],
    node_name: Optional[str] = None,
    opts: Optional[dict[str, Any]] = None,
) -> str:
    """Owner: invite an identity to a specific node.

    Returns:
        The invite bundle JSON; pass to the invitee who calls :func:`accept_node_invite`.
    """
    req_dict = json.loads(request_json)
    req = await parse_join_request(req_dict, session)

    isolated = bool((opts or {}).get("isolated"))
    per_node_keyring = bool(node.get("enc")) and isolated
    can_write = (opts or {}).get("write", True) is not False
    subject = CapSubject(edPubHex=req["edPubHex"], kemPubHex=req["kemPubHex"], userIdHex=req["userIdHex"])

    if node.get("enc") and not per_node_keyring:
        # LEGACY space-wide keyring path.
        await ensure_space_keyring_recipient(
            session.content_client, session.keys, space_id,  # type: ignore[arg-type]
            _recipient_for(req["kemPubHex"], req["userIdHex"]),
            session.layout,
        )

    bundle: NodeInviteBundle = {  # type: ignore[assignment]
        "spaceId": space_id,
        "nodeId": node_id,
        "nodeName": node_name or node_id,
        "kind": "node-enc" if per_node_keyring else ("space-enc" if node.get("enc") else "plaintext"),
    }

    if per_node_keyring:
        await ensure_node_keyring_recipient(
            session.content_client, session, space_id, node_id,  # type: ignore[arg-type]
            _recipient_for(req["kemPubHex"], req["userIdHex"]),
            session.layout,
        )
        bundle["keyringCap"] = mint_cap(session, subject, "nodekeyring", session.layout.node_keyring_scope(space_id, node_id))

    if not isolated:
        await add_space_member(session.account_client, space_id, session.user_id, req["userIdHex"], session)
        bundle["cap"] = mint_cap(session, subject, "content", session.layout.space_member_scope(space_id, can_write))

    if not node.get("enc") or per_node_keyring:
        bundle["nodeCap"] = mint_cap(session, subject, "objinv", session.layout.node_member_scope(space_id, node_id, can_write))
        bundle["streamCap"] = mint_cap(session, subject, "objinvlog", session.layout.node_stream_scope(space_id, node_id, can_write))

    if per_node_keyring:
        kn = cap_nonce(bundle.get("keyringCap"))
        nd = cap_nonce(bundle.get("nodeCap"))
        st = cap_nonce(bundle.get("streamCap"))
        save_node_invite_entry(space_id, node_id, req["userIdHex"], {
            "edPub": req["edPubHex"],
            "kemPub": req["kemPubHex"],
            "caps": {
                **({"keyring": kn} if kn else {}),
                **({"node": nd} if nd else {}),
                **({"stream": st} if st else {}),
            },
        })

    return json.dumps(bundle)


# ── acceptNodeInvite ──────────────────────────────────────────────────────────


_VALID_INVITE_KINDS = frozenset({"plaintext", "space-enc", "node-enc"})


async def accept_node_invite(session: "Session", bundle_json: str) -> str:
    """Invitee: accept a node invite — store the caps and return the nodeId."""
    bundle = json.loads(bundle_json)
    space_id = bundle.get("spaceId")
    node_id = bundle.get("nodeId")
    if not space_id or not node_id:
        raise ValueError("Invalid node invite.")

    kind = bundle.get("kind")
    if kind is not None and kind not in _VALID_INVITE_KINDS:
        raise ValueError(f"Invalid node invite: unknown kind {kind!r}.")

    def _assert_for_us(cap: Any, label: str) -> bool:
        if not cap:
            return False
        try:
            assert_cap_for_me(cap, session)
            return True
        except ValueError:
            return False

    has_space_cap = _assert_for_us(bundle.get("cap"), "cap")
    has_node_cap = _assert_for_us(bundle.get("nodeCap"), "nodeCap")
    if not has_space_cap and not has_node_cap:
        raise ValueError("Invalid node invite.")

    if has_space_cap:
        save_space_access_entry(space_id, {"kind": "member", "cap": json.dumps(bundle["cap"])})

    tiers = [
        ("nodeCap", save_node_access_entry),
        ("streamCap", save_node_stream_access_entry),
        ("keyringCap", save_node_keyring_access_entry),
    ]
    for field, save_fn in tiers:
        cap = bundle.get(field)
        if cap and _assert_for_us(cap, field):
            save_fn(space_id, node_id, {"kind": "member", "cap": json.dumps(cap)})

    return node_id


# ── revokeNodeAccess ──────────────────────────────────────────────────────────


async def revoke_node_access(
    session: "Session",
    space_id: str,
    node_id: str,
    user_id: str,
    opts: dict[str, Any],
) -> dict[str, Any]:
    """Revoke a previously-issued isolated per-node-keyring invite."""
    invite = get_node_invite_entry(space_id, node_id, user_id)
    if not invite:
        raise ValueError(
            f"revoke_node_access: no stored invite for {user_id!r} on node {node_id!r}"
        )
    caps = invite.get("caps", {})
    if not caps.get("keyring"):
        raise ValueError(
            "revoke_node_access: no keyring cap stored — only per-node-keyring (isolated enc) invites support this function"
        )

    prior_revoked = list(opts.get("priorRevoked") or [])
    if caps.get("node"):
        prior_revoked.append({"sub": invite["edPub"], "nonce": caps["node"]["nonce"], "exp": caps["node"]["exp"]})
    if caps.get("stream"):
        prior_revoked.append({"sub": invite["edPub"], "nonce": caps["stream"]["nonce"], "exp": caps["stream"]["exp"]})

    member_entry = {
        "sub": invite["edPub"],
        "nonce": caps["keyring"]["nonce"],
        "exp": caps["keyring"]["exp"],
        "subKem": invite["kemPub"],
    }
    return await evict_keyring_member(
        session.content_client,
        session,
        session.layout.node_keyring_name(space_id, node_id),
        member_entry,
        opts["generation"],
        prior_revoked,
    )


# ── Link-based node invite ────────────────────────────────────────────────────


def encode_node_invite_link(origin: str, token: NodeInviteLinkToken) -> str:
    return encode_link_fragment(origin, "join/node", dict(token))


def decode_node_invite_link(fragment: str) -> NodeInviteLinkToken:
    def validate(tok: Any) -> Optional[dict]:
        if not isinstance(tok, dict):
            return None
        if not tok.get("spaceId") or not tok.get("nodeId") or not tok.get("cap") or not tok.get("key"):
            return None
        return tok

    raw = decode_link_fragment(fragment, validate, "That node invite link is malformed or incomplete.")
    token: NodeInviteLinkToken = {  # type: ignore[assignment]
        "v": 1,
        "spaceId": raw["spaceId"],
        "nodeId": raw["nodeId"],
        "nodeName": raw.get("nodeName") or raw["nodeId"],
        "cap": raw["cap"],
        "key": raw["key"],
        "write": bool(raw.get("write")),
    }
    if "streamCap" in raw:
        token["streamCap"] = raw["streamCap"]
    if "keyringCap" in raw:
        token["keyringCap"] = raw["keyringCap"]
    return token


async def create_node_invite_link(
    session: "Session",
    space_id: str,
    node_id: str,
    node_name: str,
    node: dict[str, Any],
    write: bool,
    origin: str,
    opts: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Owner: create a shareable invite link for a specific node.

    Returns:
        ``{"token": NodeInviteLinkToken, "link": str}``.
    """
    subject, ed_priv, kem_priv = await ephemeral_subject_async(session)
    ephemeral_user_id = subject["userIdHex"]

    isolated = bool((opts or {}).get("isolated"))
    per_node_keyring = bool(node.get("enc")) and isolated

    if not isolated:
        await add_space_member(session.account_client, space_id, session.user_id, ephemeral_user_id, session)

    if node.get("enc") and not per_node_keyring:
        await ensure_space_keyring_recipient(
            session.content_client, session.keys, space_id,  # type: ignore[arg-type]
            _recipient_for(subject["kemPubHex"], ephemeral_user_id),
            session.layout,
        )

    keyring_cap = None
    if per_node_keyring:
        await ensure_node_keyring_recipient(
            session.content_client, session, space_id, node_id,  # type: ignore[arg-type]
            _recipient_for(subject["kemPubHex"], ephemeral_user_id),
            session.layout,
        )
        keyring_cap = mint_cap(session, subject, "nodekeyring", session.layout.node_keyring_scope(space_id, node_id))

    if node.get("enc") and not per_node_keyring:
        cap = mint_cap(session, subject, "content", session.layout.space_member_scope(space_id, write))
    else:
        cap = mint_cap(session, subject, "objinv", session.layout.node_member_scope(space_id, node_id, write))

    stream_cap = None
    if not node.get("enc") or per_node_keyring:
        stream_cap = mint_cap(session, subject, "objinvlog", session.layout.node_stream_scope(space_id, node_id, write))

    token: NodeInviteLinkToken = {  # type: ignore[assignment]
        "v": 1,
        "spaceId": space_id,
        "nodeId": node_id,
        "nodeName": node_name,
        "cap": cap,
        "key": ed_priv,
        "write": write,
    }
    if stream_cap is not None:
        token["streamCap"] = stream_cap
    if keyring_cap is not None:
        token["keyringCap"] = keyring_cap

    return {"token": token, "link": encode_node_invite_link(origin, token)}


async def join_node_by_link(session: "Session", token: NodeInviteLinkToken) -> str:
    """Any user: access a node by redeeming an invite link token."""
    assert_cap_not_expired(token["cap"], "That node invite link is no longer usable")
    access_payload = {"cap": token["cap"], "key": token["key"], "write": token.get("write", False)}
    sealed = seal_to_self(session, json.dumps(access_payload))

    sealed_stream = None
    if "streamCap" in token:
        sealed_stream = seal_to_self(session, json.dumps({"cap": token["streamCap"], "key": token["key"], "write": token.get("write", False)}))

    sealed_keyring = None
    if "keyringCap" in token:
        sealed_keyring = seal_to_self(session, json.dumps({"cap": token["keyringCap"], "key": token["key"], "write": False}))

    space_id = token["spaceId"]
    node_id = token["nodeId"]

    # Store as a node space entry in pubAccess under compound key.
    from starfish_spaces.registry import update_spaces_doc
    node_space = build_space(node_id, token.get("nodeName") or node_id)

    def mutator(cur: dict[str, Any]) -> Optional[dict[str, Any]]:
        exists = any(s.get("id") == node_id for s in cur["spaces"] if isinstance(s, dict))
        new_pub = {
            **cur["pubAccess"],
            f"{space_id}:{node_id}": sealed,
        }
        if sealed_stream:
            new_pub[f"{space_id}:{node_id}:stream"] = sealed_stream
        if sealed_keyring:
            new_pub[f"{space_id}:{node_id}:keyring"] = sealed_keyring
        return {
            "spaces": cur["spaces"] if exists else [*cur["spaces"], {"id": node_id, "name": token.get("nodeName") or node_id, "members": 1}],
            "caps": cur["caps"],
            "pubAccess": new_pub,
        }

    await update_spaces_doc(session.account_client, session, mutator)

    save_node_access_entry(space_id, node_id, {"kind": "link", "cap": token["cap"], "key": token["key"], "write": token.get("write", False)})
    if "streamCap" in token:
        save_node_stream_access_entry(space_id, node_id, {"kind": "link", "cap": token["streamCap"], "key": token["key"], "write": token.get("write", False)})
    if "keyringCap" in token:
        save_node_keyring_access_entry(space_id, node_id, {"kind": "link", "cap": token["keyringCap"], "key": token["key"], "write": False})

    return node_id


# ── Raw link-token read/write (no Session) ────────────────────────────────────


async def read_node_with_link_cap(
    token: NodeInviteLinkToken,
    opts: dict[str, str],
) -> Any:
    """Read a node's ``objinv`` content using only a link token (no Session)."""
    import httpx

    space_id = token["spaceId"]
    node_id = token["nodeId"]
    namespace = opts.get("namespace", "")
    base_url = opts.get("baseUrl", "")
    path = f"/pull/spaces/{space_id}/objects/{node_id}/objinv"
    url = base_url + (f"/v1/{namespace}" if namespace else "") + path

    from starfish_spaces.client import build_auth_headers
    headers = build_auth_headers(token["cap"], token["key"], "GET", path, None, base_url)
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)
    if resp.status_code != 200:
        raise RuntimeError(f"read_node_with_link_cap failed: HTTP {resp.status_code}")
    return resp.json().get("data")


async def write_node_with_link_cap(
    token: NodeInviteLinkToken,
    body: Any,
    opts: dict[str, str],
    base_hash: Optional[str] = None,
) -> None:
    """Write to a node's ``objinv`` content using only a link token (no Session)."""
    import httpx

    space_id = token["spaceId"]
    node_id = token["nodeId"]
    namespace = opts.get("namespace", "")
    base_url = opts.get("baseUrl", "")
    path = f"/push/spaces/{space_id}/objects/{node_id}/objinv"
    url = base_url + (f"/v1/{namespace}" if namespace else "") + path

    from starfish_spaces.client import build_auth_headers
    headers = build_auth_headers(token["cap"], token["key"], "POST", path, None, base_url)
    headers["Content-Type"] = "application/json"
    payload = json.dumps({"data": body, "baseHash": base_hash})
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, content=payload, headers=headers)
    if resp.status_code != 200:
        raise RuntimeError(f"write_node_with_link_cap failed: HTTP {resp.status_code}")


__all__ = [
    "CreateNodeInput",
    "StoredNodeInvite",
    "save_node_invite_entry",
    "get_node_invite_entry",
    "clear_node_invite_store",
    "serialize_node_invite_store",
    "hydrate_node_invite_store",
    "create_node",
    "set_node_access",
    "invite_to_node",
    "accept_node_invite",
    "revoke_node_access",
    "encode_node_invite_link",
    "decode_node_invite_link",
    "create_node_invite_link",
    "join_node_by_link",
    "read_node_with_link_cap",
    "write_node_with_link_cap",
]
