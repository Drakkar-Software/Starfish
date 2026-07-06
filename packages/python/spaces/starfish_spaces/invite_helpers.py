"""Shared building blocks for space + node invite/link/accept/revoke flows.

One implementation per concept, parameterized by collection + scope.  Used by
:mod:`starfish_spaces.members` and :mod:`starfish_spaces.nodes`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Optional, TypedDict

import time

from starfish_identities import generate_device_keys, mint_device_cap
from starfish_sharing.cap_mint import MintOpts, mint_member_cap
from starfish_sharing.evict import evict_member

from starfish_spaces.request_verify import verify_kem_sig
from starfish_spaces.token_types import JoinRequest

if TYPE_CHECKING:
    from starfish_sdk import StarfishClient
    from starfish_spaces.session import Session


# ── Types ─────────────────────────────────────────────────────────────────────


class CapSubject(TypedDict):
    """Ed25519 + KEM pubkeys + userId for a cap-cert subject."""

    edPubHex: str
    kemPubHex: str
    userIdHex: str


# ── Helpers ───────────────────────────────────────────────────────────────────


def adder_of(session: "Session") -> dict[str, str]:
    """Extract the ``AdderKeys`` from a session."""
    return {
        "edPriv": session.keys["edPriv"],
        "edPub": session.keys["edPub"],
        "kemPriv": session.keys["kemPriv"],
    }


def mint_cap(
    session: "Session",
    subject: CapSubject,
    collection: str,
    scope: dict[str, Any],
    opts: Optional[MintOpts] = None,
) -> Any:
    """Mint a member cap-cert from ``session`` for ``subject`` into ``collection`` with ``scope``.

    ``collection`` is the single collection name the cap grants access to (matches
    ``starfish_sharing.mint_member_cap``'s signature). ``opts`` bounds validity via
    ``ttl_sec`` / ``expires_at`` / ``nbf`` (default 30-day TTL when omitted).
    """
    sub = {
        "edPubHex": subject["edPubHex"],
        "kemPubHex": subject["kemPubHex"],
        "userIdHex": subject["userIdHex"],
    }
    return mint_member_cap(
        session.keys["edPriv"],
        session.keys["edPub"],
        sub,  # type: ignore[arg-type]
        collection,
        scope,
        opts,
    )


def assert_cap_not_expired(cap_cert: Any, err_prefix: str) -> None:
    """Reject a cap that has expired or is not yet valid (from its ``nbf``/``exp``).

    The server enforces ``nbf``/``exp`` on every request regardless; this gives
    link redemption a clear, immediate error instead of a silent post-join pull
    failure. A cap with no ``exp`` is treated as non-expiring — the server stays
    the backstop.

    Raises:
        ValueError: ``"{err_prefix}: this invite link has expired."`` /
            ``"...is not yet valid."``.
    """
    if not isinstance(cap_cert, dict):
        return
    now = int(time.time())
    nbf = cap_cert.get("nbf")
    exp = cap_cert.get("exp")
    if nbf is not None and now < nbf:
        raise ValueError(f"{err_prefix}: this invite link is not yet valid.")
    if exp is not None and now >= exp:
        raise ValueError(f"{err_prefix}: this invite link has expired.")


def cap_nonce(cap_cert: Any) -> Optional[dict[str, Any]]:
    """Extract ``{nonce, exp}`` from a CapCert, or ``None`` if absent."""
    if not isinstance(cap_cert, dict):
        return None
    nonce = cap_cert.get("nonce")
    exp = cap_cert.get("exp")
    if nonce is None:
        return None
    return {"nonce": nonce, "exp": exp}


async def parse_join_request(
    join_req: JoinRequest,
    session: "Session",
) -> CapSubject:
    """Validate a :class:`JoinRequest` and return the requester's identity.

    Checks:
    1. ``kemSig`` is a valid Ed25519 signature of ``kemPub`` by ``edPub``.
    2. ``userId`` matches ``session.user_id_from_ed_pub(join_req.edPub)``.

    Raises:
        ValueError: on any validation failure.
    """
    ed_pub = join_req.get("edPub", "")
    kem_pub = join_req.get("kemPub", "")
    kem_sig = join_req.get("kemSig", "")
    user_id = join_req.get("userId", "")

    if not verify_kem_sig(ed_pub, kem_pub, kem_sig):
        raise ValueError("JoinRequest kemSig is invalid — kemPub ownership not proven")

    expected_user_id = await session.user_id_from_ed_pub(ed_pub)
    if user_id != expected_user_id:
        raise ValueError(
            f"JoinRequest userId mismatch: got {user_id!r}, expected {expected_user_id!r}"
        )

    return CapSubject(edPubHex=ed_pub, kemPubHex=kem_pub, userIdHex=user_id)


def ephemeral_subject(session: "Session") -> tuple[CapSubject, str, str]:
    """Generate a throwaway ephemeral keypair for invite-link tokens.

    Returns:
        ``(subject, ed_priv_hex, kem_priv_hex)`` — the subject's public identifiers
        and its private keys so the token holder can authenticate.
    """
    import asyncio

    keys = generate_device_keys()

    # Derive userId for the ephemeral subject.
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            # If we're already in an async context, run in thread pool.
            # Callers should ideally await this — but since session has an async
            # hook, we derive a simple sha256-based userId synchronously as a
            # fallback for the ephemeral case where the derivation is deterministic.
            import hashlib
            user_id = hashlib.sha256(bytes.fromhex(keys["edPub"])).digest()[:16].hex()
        else:
            user_id = loop.run_until_complete(session.user_id_from_ed_pub(keys["edPub"]))
    except Exception:
        import hashlib
        user_id = hashlib.sha256(bytes.fromhex(keys["edPub"])).digest()[:16].hex()

    subject = CapSubject(
        edPubHex=keys["edPub"],
        kemPubHex=keys["kemPub"],
        userIdHex=user_id,
    )
    return subject, keys["edPriv"], keys["kemPriv"]


async def ephemeral_subject_async(session: "Session") -> tuple[CapSubject, str, str]:
    """Async version of :func:`ephemeral_subject` — preferred in async contexts."""
    keys = generate_device_keys()
    user_id = await session.user_id_from_ed_pub(keys["edPub"])
    subject = CapSubject(
        edPubHex=keys["edPub"],
        kemPubHex=keys["kemPub"],
        userIdHex=user_id,
    )
    return subject, keys["edPriv"], keys["kemPriv"]


def assert_cap_for_me(cap_cert: Any, session: "Session") -> None:
    """Raise :class:`ValueError` unless ``cap_cert`` is a member cap for this device.

    Checks:
    - ``cap_cert.kind == "member"``
    - ``cap_cert.sub == session.keys.edPub``
    """
    if not isinstance(cap_cert, dict):
        raise ValueError("cap_cert must be a dict")
    if cap_cert.get("kind") != "member":
        raise ValueError(f"Expected cap kind='member', got {cap_cert.get('kind')!r}")
    if cap_cert.get("sub") != session.keys["edPub"]:
        raise ValueError(
            f"cap_cert.sub {cap_cert.get('sub')!r} does not match my edPub "
            f"{session.keys['edPub']!r}"
        )


async def evict_keyring_member(
    client: "StarfishClient",
    session: "Session",
    collection_name: str,
    member_entry: dict[str, Any],
    generation: int,
    prior_revoked: Optional[list[dict[str, Any]]] = None,
    submit_revocation: Optional[Callable[[dict[str, Any]], Awaitable[None]]] = None,
) -> dict[str, Any]:
    """Rotate the keyring and submit a :class:`RevocationList` for ``member_entry``.

    Args:
        client:          The StarfishClient to use.
        session:         The owner's session.
        collection_name: The keyring collection name.
        member_entry:    The member entry dict (``{sub, subKem, ...}``).
        generation:      The new revocation list generation number.
        prior_revoked:   Previously revoked entries to include in the new list.
        submit_revocation: Callback the signed :class:`RevocationList` is POSTed
            to.  When ``None`` a no-op is used (rotation alone gives forward
            secrecy); callers that need live revocation must forward one.

    Returns:
        The updated revocation list dict.
    """
    from starfish_spaces.node_keyring import owner_trusted_adders

    trusted = owner_trusted_adders(session)

    async def _noop_submit(revocation_list: dict[str, Any]) -> None:
        # Callers that need live revocation list submission should pass a
        # callback via opts.  For the in-process spaces domain the default
        # is a no-op; forward-secrecy via keyring rotation is sufficient.
        pass

    result = await evict_member(
        client,
        members_collection=collection_name,
        member=member_entry,
        iss_ed_pub_hex=session.keys["edPub"],
        iss_ed_priv_hex=session.keys["edPriv"],
        generation=generation,
        submit_revocation=submit_revocation or _noop_submit,
        keyring_collection=collection_name,
        adder={
            "edPriv": session.keys["edPriv"],
            "edPub": session.keys["edPub"],
            "kemPriv": session.keys["kemPriv"],
        },
        trusted_adders=trusted,
        prior_revoked=prior_revoked or [],
        rotate=True,
        revoke=True,
    )
    return result


__all__ = [
    "CapSubject",
    "adder_of",
    "mint_cap",
    "cap_nonce",
    "assert_cap_not_expired",
    "parse_join_request",
    "ephemeral_subject",
    "ephemeral_subject_async",
    "assert_cap_for_me",
    "evict_keyring_member",
]
