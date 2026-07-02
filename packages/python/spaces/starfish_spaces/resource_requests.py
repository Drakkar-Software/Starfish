"""Sealed resource-request inbox — the generic "request-to-create" pattern.

A REQUESTER holds only the owner's **public identity link** (no authority, safe
to share openly). They seal a typed resource-creation request to the owner's KEM
key and append it anonymously to the owner's existing ``inbox/{ownerId}/{shard}``
collection. The OWNER's reconciler trial-unseals pending requests, creates the
requested node in its space with its own owner cap, and seals a narrow per-node
cap back to the requester's inbox.

Security:
- Offline binding: ``verify_identity_link_binding(owner_link, session)`` before sealing.
- Sender authenticity: ``sealed.entry.addedBy === req.requester.edPub``.
- Accept/reject gate: owner decides; nothing lands in the space automatically.
- Idempotency: nodes carry ``meta.reqId``; ``scan_resource_requests`` skips
  fulfilled reqIds.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Callable, Optional

from starfish_protocol.random import random_id

from starfish_spaces.account_seal import seal_to_recipient, unseal_from_recipient
from starfish_spaces.identity_link import (
    IdentityLink,
    verify_identity_link_binding,
    verify_identity_link_keys,
)
from starfish_spaces.inbox import inbox_shard, inbox_shards, pull_inbox
from starfish_spaces.keyed_store import create_keyed_store
from starfish_spaces.nodes import accept_node_invite, create_node, invite_to_node
from starfish_spaces.object_index import read_object_tree
from starfish_spaces.request_verify import sign_kem_sig, verify_kem_sig
from starfish_spaces.token_types import ResourceGrant, ResourceReject, ResourceRequest

if TYPE_CHECKING:
    from starfish_spaces.session import Session


# ── AAD helpers ───────────────────────────────────────────────────────────────


def _inbox_aad(session: "Session", recipient_id: str, shard: str, kind: str) -> str:
    return f"{session.inbox_aad_namespace}:{recipient_id}:{shard}:{kind}"


async def _try_unseal_inbox(
    session: "Session",
    sealed: dict[str, Any],
    shard: str,
    mkind: Optional[str],
    default_kind: str,
) -> Optional[str]:
    try:
        aad = _inbox_aad(session, session.user_id, shard, mkind or default_kind)
        return unseal_from_recipient(session.keys, sealed, aad)
    except Exception:
        return None


# ── Append sealed message to a recipient's inbox ──────────────────────────────


async def _seal_append(
    session: "Session",
    recipient_user_id: str,
    recipient_kem_pub: str,
    kind: str,
    obj: Any,
) -> None:
    """Seal ``obj`` to ``recipient_kem_pub`` and append it to the current-shard inbox."""
    import time as _time
    from starfish_spaces.client import make_anon_space_client, ClientOpts

    shard = inbox_shard()
    aad = _inbox_aad(session, recipient_user_id, shard, kind)
    sealed = seal_to_recipient(session.keys, "", recipient_kem_pub, json.dumps(obj), aad)

    element: dict[str, Any] = {
        "sealed": sealed,
        "ts": int(_time.time() * 1000),
        "mkind": kind,
    }

    anon_opts: ClientOpts = {"baseUrl": session.base_url, "namespace": session.namespace}  # type: ignore[misc]
    anon_client = make_anon_space_client(anon_opts)
    push_path = session.layout.inbox_push(recipient_user_id, shard)
    await anon_client.append_anonymous(push_path, element)


# ── Generic inbox scan ────────────────────────────────────────────────────────


async def _scan_inbox(
    session: "Session",
    default_kind: str,
    handle: Callable[[Any, dict[str, Any]], Any],
) -> None:
    """Walk both current + previous shards, trial-unseal each element, call ``handle``."""
    for shard in inbox_shards():
        items = await pull_inbox(session.account_client, session, session.user_id, shard)
        for item in items:
            payload = item.get("data") if isinstance(item, dict) else None
            if not isinstance(payload, dict) or not payload.get("sealed"):
                continue
            sealed = payload["sealed"]
            plaintext = await _try_unseal_inbox(session, sealed, shard, payload.get("mkind"), default_kind)
            if plaintext is None:
                continue
            try:
                parsed = json.loads(plaintext)
            except Exception:
                continue
            result = handle(parsed, sealed)
            if hasattr(result, "__await__"):
                await result


# ── Owner-store: reqId → owner edPub ─────────────────────────────────────────

_req_id_owner_store = create_keyed_store()


def save_req_id_owner(req_id: str, owner_ed_pub: str) -> None:
    """Record the owner edPub for a submitted request."""
    _req_id_owner_store.set(req_id, owner_ed_pub)


def serialize_req_id_owner_store() -> str:
    return _req_id_owner_store.serialize()


def hydrate_req_id_owner_store(raw: str) -> None:
    _req_id_owner_store.hydrate(raw)


def clear_req_id_owner_store() -> None:
    _req_id_owner_store.clear_all()


# ── REQUESTER: submit a request ───────────────────────────────────────────────


async def submit_resource_request(
    session: "Session",
    owner_link: IdentityLink,
    opts: dict[str, Any],
) -> dict[str, str]:
    """REQUESTER: send a sealed resource-creation request to an owner's inbox.

    Args:
        session:    The requester's session.
        owner_link: The owner's decoded :class:`IdentityLink`.
        opts:       ``{spaceId, nodeType, title, meta?, message?}``.

    Returns:
        ``{"reqId": str}`` — save it to track fulfilment.

    Raises:
        ValueError: if sending to yourself or if the owner link is malformed.
    """
    if owner_link.owner_id == session.user_id:
        raise ValueError("Cannot send a request to yourself.")
    if not await verify_identity_link_binding(owner_link, session):
        raise ValueError("That identity link is malformed — ownerId does not match edPub.")
    await verify_identity_link_keys(owner_link, session)

    req_id = random_id()
    kem_sig = sign_kem_sig(session.keys["kemPub"], session.keys["edPriv"])
    request: ResourceRequest = {  # type: ignore[assignment]
        "v": 1,
        "kind": "create-resource",
        "reqId": req_id,
        "spaceId": opts["spaceId"],
        "nodeType": opts["nodeType"],
        "title": opts["title"],
        **({"meta": opts["meta"]} if opts.get("meta") else {}),
        **({"message": opts["message"]} if opts.get("message") else {}),
        "requester": {
            "userId": session.user_id,
            "edPub": session.keys["edPub"],
            "kemPub": session.keys["kemPub"],
            "kemSig": kem_sig,
        },
    }

    save_req_id_owner(req_id, owner_link.ed_pub)
    await _seal_append(session, owner_link.owner_id, owner_link.kem_pub, "request", request)
    return {"reqId": req_id}


# ── OWNER: scan pending requests ──────────────────────────────────────────────


class PendingRequest(dict):
    """A pending request returned by :func:`scan_resource_requests`."""
    pass


async def scan_resource_requests(
    session: "Session",
    space_ids: Optional[frozenset[str]] = None,
) -> list[dict[str, Any]]:
    """OWNER: scan this session's inbox for pending ``create-resource`` requests.

    Returns:
        List of ``{"req": ResourceRequest, "senderEdPub": str}`` dicts.
    """
    tree_cache: dict[str, list[Any]] = {}
    out: list[dict[str, Any]] = []

    async def handle(parsed: Any, sealed: dict[str, Any]) -> None:
        req = parsed if isinstance(parsed, dict) else {}

        if (
            req.get("v") != 1
            or req.get("kind") != "create-resource"
            or not isinstance(req.get("reqId"), str)
            or not isinstance(req.get("spaceId"), str)
            or not isinstance(req.get("nodeType"), str)
            or not isinstance(req.get("title"), str)
            or not isinstance(req.get("requester"), dict)
        ):
            return

        requester = req["requester"]
        if not (
            isinstance(requester.get("edPub"), str)
            and isinstance(requester.get("kemPub"), str)
            and isinstance(requester.get("userId"), str)
            and isinstance(requester.get("kemSig"), str)
        ):
            return

        # Verify sender authenticity from the sealed entry's addedBy field.
        # Fail-closed: a missing/empty addedBy is treated as a mismatch.
        added_by = sealed.get("addedBy") or (sealed.get("entry", {}) or {}).get("addedBy")
        if added_by != requester["edPub"]:
            return

        if (await session.user_id_from_ed_pub(requester["edPub"])) != requester["userId"]:
            return

        if not verify_kem_sig(requester["edPub"], requester["kemPub"], requester["kemSig"]):
            return

        if space_ids is not None and req["spaceId"] not in space_ids:
            return

        # Check if already fulfilled (node with meta.reqId exists in space).
        space_id = req["spaceId"]
        if space_id not in tree_cache:
            try:
                tree = await read_object_tree(session.content_client, session, space_id)
                tree_cache[space_id] = tree
            except Exception:
                tree_cache[space_id] = []

        already_fulfilled = any(
            (getattr(n, "meta", None) or {}).get("reqId") == req["reqId"]
            for n in tree_cache[space_id]
        )
        if already_fulfilled:
            return

        out.append({"req": req, "senderEdPub": requester["edPub"]})

    await _scan_inbox(session, "request", handle)
    return out


# ── OWNER: accept a request ───────────────────────────────────────────────────


async def accept_resource_request(
    session: "Session",
    pending: dict[str, Any],
    opts: Optional[dict[str, Any]] = None,
) -> dict[str, str]:
    """OWNER: accept a pending resource request.

    Creates the node (via ``opts.create`` or the default :func:`create_node`),
    grants the requester a narrow per-node cap sealed back to their inbox.

    Returns:
        ``{"spaceId": str, "nodeId": str}``.
    """
    req: dict[str, Any] = pending["req"]
    create_fn = (opts or {}).get("create")

    if create_fn:
        result = await create_fn(session, req)
        node_id = result["nodeId"]
    else:
        node = await create_node(session, req["spaceId"], {
            "type": req["nodeType"],
            "title": req["title"],
            "meta": {**(req.get("meta") or {}), "reqId": req["reqId"]},
            "access": "invite",
            "enc": bool((opts or {}).get("enc")),
        })
        node_id = node.id

    requester = req["requester"]
    bundle_json = await invite_to_node(
        session, req["spaceId"], node_id,
        json.dumps(requester),
        {"enc": bool((opts or {}).get("enc"))},
        req["title"],
        {"isolated": True, "write": (opts or {}).get("write", True)},
    )

    grant: ResourceGrant = {  # type: ignore[assignment]
        "v": 1,
        "kind": "grant",
        "reqId": req["reqId"],
        "spaceId": req["spaceId"],
        "nodeId": node_id,
        "bundle": bundle_json,
    }
    await _seal_append(session, requester["userId"], requester["kemPub"], "grant", grant)
    return {"spaceId": req["spaceId"], "nodeId": node_id}


# ── OWNER: reject a request ───────────────────────────────────────────────────


async def reject_resource_request(
    session: "Session",
    pending: dict[str, Any],
    reason: Optional[str] = None,
) -> None:
    """OWNER: reject a pending request."""
    req = pending["req"]
    requester = req["requester"]
    rejection: ResourceReject = {  # type: ignore[assignment]
        "v": 1,
        "kind": "reject",
        "reqId": req["reqId"],
        **({"reason": reason} if reason else {}),
    }
    await _seal_append(session, requester["userId"], requester["kemPub"], "reject", rejection)


# ── REQUESTER: scan grants ────────────────────────────────────────────────────


async def scan_resource_grants(
    session: "Session",
    seen_req_ids: Optional[set[str]] = None,
) -> list[ResourceGrant]:
    """REQUESTER: scan this session's inbox for resource grants."""
    out: list[ResourceGrant] = []
    seen = seen_req_ids if seen_req_ids is not None else set()

    def handle(parsed: Any, sealed: dict[str, Any]) -> None:
        msg = parsed if isinstance(parsed, dict) else {}
        if msg.get("v") != 1 or msg.get("kind") != "grant":
            return
        if not (isinstance(msg.get("reqId"), str) and isinstance(msg.get("spaceId"), str)
                and isinstance(msg.get("nodeId"), str) and isinstance(msg.get("bundle"), str)):
            return

        req_id = msg["reqId"]
        expected_owner = _req_id_owner_store.get(req_id)
        added_by = sealed.get("addedBy") or (sealed.get("entry", {}) or {}).get("addedBy")
        if expected_owner and added_by != expected_owner:
            return
        if req_id in seen:
            return
        seen.add(req_id)
        out.append(msg)  # type: ignore[arg-type]

    await _scan_inbox(session, "grant", handle)
    return out


# ── REQUESTER: scan rejects ───────────────────────────────────────────────────


async def scan_resource_rejects(
    session: "Session",
    seen_req_ids: Optional[set[str]] = None,
) -> list[ResourceReject]:
    """REQUESTER: scan this session's inbox for resource rejections."""
    out: list[ResourceReject] = []
    seen = seen_req_ids if seen_req_ids is not None else set()

    def handle(parsed: Any, sealed: dict[str, Any]) -> None:
        msg = parsed if isinstance(parsed, dict) else {}
        if msg.get("v") != 1 or msg.get("kind") != "reject" or not isinstance(msg.get("reqId"), str):
            return
        req_id = msg["reqId"]
        expected_owner = _req_id_owner_store.get(req_id)
        added_by = sealed.get("addedBy") or (sealed.get("entry", {}) or {}).get("addedBy")
        if expected_owner and added_by != expected_owner:
            return
        if req_id in seen:
            return
        seen.add(req_id)
        out.append(msg)  # type: ignore[arg-type]

    await _scan_inbox(session, "reject", handle)
    return out


# ── REQUESTER: accept a grant ─────────────────────────────────────────────────


async def accept_resource_grant(
    session: "Session",
    grant: ResourceGrant,
) -> dict[str, str]:
    """REQUESTER: store the per-node cap and return the node reference."""
    node_id = await accept_node_invite(session, grant["bundle"])
    return {"spaceId": grant["spaceId"], "nodeId": node_id}


__all__ = [
    "PendingRequest",
    "save_req_id_owner",
    "serialize_req_id_owner_store",
    "hydrate_req_id_owner_store",
    "clear_req_id_owner_store",
    "submit_resource_request",
    "scan_resource_requests",
    "accept_resource_request",
    "reject_resource_request",
    "scan_resource_grants",
    "scan_resource_rejects",
    "accept_resource_grant",
]
