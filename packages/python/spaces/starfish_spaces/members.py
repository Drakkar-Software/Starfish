"""Space membership — invite-based (member cap) and link-based (open access).

MEMBER join: the owner records the invitee in the roster, mints a space-scoped
member cap, and adds the invitee to the space-wide keyring (if it exists) so
they can decrypt ``enc`` content. The invitee stores a ``{kind:'member'}`` entry.

LINK join: the owner mints an ephemeral Ed/KEM keypair whose *private* key ships
inside a URL-fragment token, adds the ephemeral userId to the roster so the server
grants ``space:member``, and mints a member cap scoped to that ephemeral subject.
Any bearer of the link stores a ``{kind:'link'}`` entry.

REVOCATION: ``remove_space_member`` removes the userId from the server roster so
the server stops granting ``space:member`` to new requests.  For ``enc`` spaces,
call :func:`revoke_space_access` instead — it also rotates the space keyring.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Callable, Optional, TypedDict

from starfish_protocol.encoding import decode_link_fragment, encode_link_fragment

from starfish_spaces.account_seal import seal_to_self, unseal_from_self
from starfish_spaces.client import (
    add_space_keyring_recipient,
    ensure_space_keyring_recipient,
)
from starfish_spaces.invite_helpers import (
    CapSubject,
    assert_cap_for_me,
    cap_nonce,
    ephemeral_subject_async,
    evict_keyring_member,
    mint_cap,
    parse_join_request,
)
from starfish_spaces.keyed_store import create_composed_store
from starfish_spaces.layout import RECIPIENT_LABEL_LEN
from starfish_spaces.registry import (
    add_joined_space_with_cap,
    add_joined_space_with_link_access,
    add_space_member,
    build_space,
    read_spaces,
    remove_space_member,
    update_spaces_doc,
)
from starfish_spaces.request_verify import sign_kem_sig
from starfish_spaces.space_access_store import (
    hydrate_space_access_store,
    local_space_access_entries,
    save_space_access_entry,
)
from starfish_spaces.token_types import JoinRequest, SpaceInviteLinkToken

if TYPE_CHECKING:
    from starfish_spaces.config import SealedBlob
    from starfish_spaces.session import Session


# ── Utilities ─────────────────────────────────────────────────────────────────


def _recipient_for(sub_kem: str, user_id: str) -> dict[str, str]:
    return {"subKem": sub_kem, "userId": user_id, "label": user_id[:RECIPIENT_LABEL_LEN]}


# ── JoinRequest helpers ───────────────────────────────────────────────────────


def make_join_request(session: "Session") -> str:
    """Build a JSON join-request string from the current session's keys."""
    kem_sig = sign_kem_sig(session.keys["kemPub"], session.keys["edPriv"])
    req: JoinRequest = {
        "edPub": session.keys["edPub"],
        "kemPub": session.keys["kemPub"],
        "userId": session.user_id,
        "kemSig": kem_sig,
    }
    return json.dumps(req)


# ── Space invite store (nonces for full eviction) ─────────────────────────────


class StoredSpaceInvite(TypedDict):
    """Retained invite data (owner-side, keyed by ``{spaceId}:{userId}``)."""

    edPub: str
    kemPub: str
    cap: dict[str, Any]  # {nonce, exp}


_space_invite_store = create_composed_store(
    compose_key=lambda space_id, user_id: f"{space_id}:{user_id}"
)


def save_space_invite_entry(space_id: str, user_id: str, entry: StoredSpaceInvite) -> None:
    """Save an invite entry for future revocation."""
    _space_invite_store.for_(space_id, user_id).set(entry)


def get_space_invite_entry(space_id: str, user_id: str) -> Optional[StoredSpaceInvite]:
    """Retrieve a stored invite entry. Returns ``None`` when absent."""
    return _space_invite_store.for_(space_id, user_id).get()


def clear_space_invite_store() -> None:
    """Clear all entries (e.g. on sign-out)."""
    _space_invite_store.store.clear_all()


def serialize_space_invite_store() -> str:
    """Snapshot the store for persistence across reloads."""
    return _space_invite_store.store.serialize()


def hydrate_space_invite_store(raw: str) -> None:
    """Restore the store after a reload (additive — does not clear existing)."""
    _space_invite_store.store.hydrate(raw)


# ── Direct invite ─────────────────────────────────────────────────────────────


async def invite_to_space(
    session: "Session",
    space_id: str,
    request_json: str,
    can_write: bool = True,
    space_name: Optional[str] = None,
) -> str:
    """Owner: invite an identity into a space.

    Records them in the roster, mints a space-scoped member cap, and adds them
    to the space-wide keyring if it exists.

    Args:
        session:      The owner's session.
        space_id:     The target space.
        request_json: JSON join-request from the invitee.
        can_write:    Whether the member gets write access.
        space_name:   Override the space name in the invite bundle.

    Returns:
        The invite bundle JSON; pass to the invitee who calls :func:`accept_space_invite`.
    """
    req_dict = json.loads(request_json)
    req = await parse_join_request(req_dict, session)
    await add_space_member(session.account_client, space_id, session.user_id, req["userIdHex"], session)

    await ensure_space_keyring_recipient(
        session.content_client, session.keys, space_id,  # type: ignore[arg-type]
        _recipient_for(req["kemPubHex"], req["userIdHex"]),
        session.layout,
    )

    subject = CapSubject(
        edPubHex=req["edPubHex"], kemPubHex=req["kemPubHex"], userIdHex=req["userIdHex"]
    )
    cap = mint_cap(session, subject, "content", session.layout.space_member_scope(space_id, can_write))
    nonce = cap_nonce(cap)
    if nonce:
        save_space_invite_entry(space_id, req["userIdHex"], {"edPub": req["edPubHex"], "kemPub": req["kemPubHex"], "cap": nonce})

    if space_name is None:
        doc = await read_spaces(session.account_client, session)
        space_name = next((s["name"] for s in doc.spaces if isinstance(s, dict) and s.get("id") == space_id), "Space") if doc.spaces else "Space"

    invite = {"spaceId": space_id, "spaceName": space_name, "cap": cap}
    return json.dumps(invite)


async def accept_space_invite(session: "Session", invite_json: str) -> Any:
    """Invitee: accept a space invite — store the cap and register the space."""
    inv = json.loads(invite_json)
    cap = inv.get("cap")
    space_id = inv.get("spaceId")
    if not cap or not space_id:
        raise ValueError("That is not a valid space invite.")
    assert_cap_for_me(cap, session)
    cap_json = json.dumps(cap)
    space = build_space(space_id, inv.get("spaceName") or "")
    await add_joined_space_with_cap(session.account_client, session, space, cap_json)
    save_space_access_entry(space_id, {"kind": "member", "cap": cap_json})
    return space


# ── Link-based joins ──────────────────────────────────────────────────────────


def encode_space_invite_link(origin: str, token: SpaceInviteLinkToken) -> str:
    """Encode a :class:`SpaceInviteLinkToken` into a URL fragment."""
    return encode_link_fragment(origin, "join", dict(token))


def decode_space_invite_link(fragment: str) -> SpaceInviteLinkToken:
    """Decode a space invite link URL fragment."""
    def validate(tok: Any) -> Optional[dict]:
        if not isinstance(tok, dict):
            return None
        if not tok.get("spaceId") or not tok.get("cap") or not tok.get("key"):
            return None
        return tok

    raw = decode_link_fragment(fragment, validate, "That space invite link is malformed or incomplete.")
    return {  # type: ignore[return-value]
        "v": 1,
        "spaceId": raw["spaceId"],
        "spaceName": raw.get("spaceName") or "Space",
        "cap": raw["cap"],
        "key": raw["key"],
        "kemPriv": raw.get("kemPriv"),
        "kemPub": raw.get("kemPub"),
        "write": bool(raw.get("write")),
    }


async def create_space_invite_link(
    session: "Session",
    space_id: str,
    space_name: str,
    write: bool,
    origin: str,
) -> dict[str, Any]:
    """Owner: create a shareable invite link for a space.

    Returns:
        ``{"token": SpaceInviteLinkToken, "link": str}``.
    """
    subject, ed_priv, kem_priv = await ephemeral_subject_async(session)
    ephemeral_user_id = subject["userIdHex"]

    cap = mint_cap(session, subject, "content", session.layout.space_member_scope(space_id, write))
    nonce = cap_nonce(cap)
    if nonce:
        save_space_invite_entry(space_id, ephemeral_user_id, {"edPub": subject["edPubHex"], "kemPub": subject["kemPubHex"], "cap": nonce})

    await add_space_member(session.account_client, space_id, session.user_id, ephemeral_user_id, session)

    await ensure_space_keyring_recipient(
        session.content_client, session.keys, space_id,  # type: ignore[arg-type]
        _recipient_for(subject["kemPubHex"], ephemeral_user_id),
        session.layout,
    )

    token: SpaceInviteLinkToken = {  # type: ignore[assignment]
        "v": 1,
        "spaceId": space_id,
        "spaceName": space_name,
        "cap": cap,
        "key": ed_priv,
        "kemPriv": kem_priv,
        "kemPub": subject["kemPubHex"],
        "write": write,
    }
    return {"token": token, "link": encode_space_invite_link(origin, token)}


async def join_space_by_link(session: "Session", token: SpaceInviteLinkToken) -> Any:
    """Any user: join a space by redeeming an invite link token."""
    access_payload = {
        "cap": token["cap"],
        "key": token["key"],
        "kemPriv": token.get("kemPriv"),
        "kemPub": token.get("kemPub"),
        "write": token.get("write", False),
    }
    sealed = seal_to_self(session, json.dumps(access_payload))
    space = build_space(token["spaceId"], token.get("spaceName") or "")
    await add_joined_space_with_link_access(session.account_client, session, space, sealed)
    save_space_access_entry(token["spaceId"], {
        "kind": "link",
        "cap": token["cap"],
        "key": token["key"],
        "kemPriv": token.get("kemPriv"),
        "kemPub": token.get("kemPub"),
        "write": token.get("write", False),
    })
    return space


# ── Device pairing ────────────────────────────────────────────────────────────


async def add_device_to_space_keyring(
    session: "Session",
    space_id: str,
    device: dict[str, str],
) -> None:
    """Add a device's KEM key as a recipient of a space's keyring.

    Call this after device pairing for each space the paired device should decrypt.
    """
    try:
        await add_space_keyring_recipient(
            session.content_client,
            session.keys,  # type: ignore[arg-type]
            session.layout.keyring_name(space_id),
            _recipient_for(device["kemPub"], device.get("userId") or ""),
        )
    except Exception:
        pass  # best-effort (keyring may not exist for non-enc spaces)


# ── Recover space access ──────────────────────────────────────────────────────


async def recover_space_access(
    session: "Session",
    server: dict[str, Any],
) -> None:
    """Single sign-in hydration: merge server-side caps + sealed link access.

    Args:
        session: The active session.
        server:  ``{"caps": {spaceId: capJson}, "pubAccess": {spaceId: SealedBlob}}``.
    """
    caps: dict[str, str] = server.get("caps") or {}
    pub_access: dict[str, Any] = server.get("pubAccess") or {}

    link_access: dict[str, Any] = {}
    for space_id, sealed_blob in pub_access.items():
        try:
            from starfish_spaces.config import SealedBlob as SealedBlobType
            sealed = sealed_blob if isinstance(sealed_blob, dict) else dict(sealed_blob)
            from starfish_spaces.account_seal import unseal_from_self as _unseal
            raw = _unseal(session, sealed)
            parsed = json.loads(raw)
            if parsed.get("cap") and parsed.get("key"):
                link_access[space_id] = parsed
        except Exception:
            pass

    await hydrate_space_access_store(session.user_id, caps, link_access)

    # Backfill local-only entries to the server.
    local = local_space_access_entries()  # list of (space_id, entry) tuples
    missing_caps = {id_: e for id_, e in local if e.get("kind") == "member" and id_ not in caps}
    missing_links = {id_: e for id_, e in local if e.get("kind") == "link" and id_ not in pub_access}

    if not missing_caps and not missing_links:
        return

    try:
        new_caps = {id_: e["cap"] for id_, e in missing_caps.items()}
        new_pub: dict[str, Any] = {}
        for id_, e in missing_links.items():
            payload = {"cap": e["cap"], "key": e["key"], "kemPriv": e.get("kemPriv"), "kemPub": e.get("kemPub"), "write": e.get("write", False)}
            sealed = seal_to_self(session, json.dumps(payload))
            new_pub[id_] = sealed

        await update_spaces_doc(session.account_client, session, lambda cur: {
            "spaces": cur["spaces"],
            "caps": {**cur["caps"], **new_caps},
            "pubAccess": {**cur["pubAccess"], **new_pub},
        })
    except Exception:
        pass


# ── Revoke space access ───────────────────────────────────────────────────────


async def revoke_space_access(
    session: "Session",
    space_id: str,
    user_id: str,
    opts: dict[str, Any],
) -> dict[str, Any]:
    """Fully evict a space member — rotates keyring AND submits revocation.

    ``opts`` must contain ``"generation": int`` and optionally
    ``"priorRevoked"`` and ``"submitRevocation"`` callback.
    """
    invite = get_space_invite_entry(space_id, user_id)
    if not invite:
        raise ValueError(
            f"revoke_space_access: no stored invite for {user_id!r} on space {space_id!r}"
            " — call save_space_invite_entry or use invite_to_space / create_space_invite_link."
        )

    member_entry = {
        "sub": invite["edPub"],
        "nonce": invite["cap"].get("nonce"),
        "exp": invite["cap"].get("exp"),
        "subKem": invite["kemPub"],
    }

    await evict_keyring_member(
        session.content_client,
        session,
        session.layout.keyring_name(space_id),
        member_entry,
        opts["generation"],
        opts.get("priorRevoked"),
        opts.get("submitRevocation"),
    )

    await remove_space_member(session.account_client, space_id, user_id, session)
    return {"revoked": True}


__all__ = [
    "StoredSpaceInvite",
    "make_join_request",
    "save_space_invite_entry",
    "get_space_invite_entry",
    "clear_space_invite_store",
    "serialize_space_invite_store",
    "hydrate_space_invite_store",
    "invite_to_space",
    "accept_space_invite",
    "encode_space_invite_link",
    "decode_space_invite_link",
    "create_space_invite_link",
    "join_space_by_link",
    "add_device_to_space_keyring",
    "recover_space_access",
    "revoke_space_access",
]
