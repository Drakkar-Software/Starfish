"""Pure-identity link tokens (v:2) — safe to publish openly.

Unlike space/node invite links (bearer credentials), an identity link carries
ONLY the owner's identity (``ownerId`` + ``edPub`` + ``kemPub`` + ``kemSig``).
The only trust anchor is the ``ownerId ↔ edPub`` derivation binding.

Primary use: the ``create_resource_request`` / ``scan_resource_requests`` flow in
:mod:`starfish_spaces.resource_requests`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from starfish_protocol.encoding import decode_link_fragment, encode_link_fragment

from starfish_spaces.request_verify import sign_kem_sig

if TYPE_CHECKING:
    from starfish_spaces.session import Session

# ── Regex constants (mirror TS; use \Z anchor + [0-9a-f] char class) ─────────

_HEX64 = re.compile(r"^[0-9a-f]{64}\Z", re.IGNORECASE)
_ED_PUB_HEX_RE = _HEX64
_KEM_PUB_HEX_RE = _HEX64
_KEM_SIG_HEX_RE = re.compile(r"^[0-9a-f]{128}\Z", re.IGNORECASE)
_USER_ID_HEX_RE = re.compile(r"^[0-9a-f]{32}\Z", re.IGNORECASE)

_MALFORMED = "That identity link is malformed or incomplete."


# ── Token shape ───────────────────────────────────────────────────────────────


@dataclass
class IdentityLink:
    """Portable public identity — the only content of an identity link.

    ``kemSig`` is an Ed25519 signature of ``hexToBytes(kemPub)`` by ``edPriv``,
    binding ``kemPub`` to ``edPub`` in a way that can be verified offline.
    """

    v: int  # always 2
    owner_id: str
    pseudo: str
    ed_pub: str
    kem_pub: str
    kem_sig: str


# ── Offline trust anchor ──────────────────────────────────────────────────────


async def verify_identity_link_binding(
    token: IdentityLink,
    session: "Session",
) -> bool:
    """Verify the hard OFFLINE binding.

    1. ``token.owner_id == sha256(token.ed_pub)[:16].hex()``
    2. ``token.kem_sig`` is a valid Ed25519 signature of ``kemPub`` by ``edPub``.

    Call before rendering anything about the owner or sending any request.
    """
    expected = await session.user_id_from_ed_pub(token.ed_pub)
    if expected != token.owner_id:
        return False
    try:
        from starfish_spaces.request_verify import verify_kem_sig
        return verify_kem_sig(token.ed_pub, token.kem_pub, token.kem_sig)
    except Exception:
        return False


# ── Encode / decode ───────────────────────────────────────────────────────────


def encode_identity_link(origin: str, path: str, token: IdentityLink) -> str:
    """Pack an identity link into a URL: ``<origin>/<path>#<base64url(token)>``."""
    payload = {
        "v": token.v,
        "ownerId": token.owner_id,
        "pseudo": token.pseudo,
        "edPub": token.ed_pub,
        "kemPub": token.kem_pub,
        "kemSig": token.kem_sig,
    }
    return encode_link_fragment(origin, path, payload)


def _validate_identity_link(tok: Any) -> Optional[dict[str, Any]]:
    """Validator for :func:`decode_link_fragment` — returns token dict or ``None``."""
    if not isinstance(tok, dict):
        return None
    if tok.get("v") != 2:
        return None
    owner_id = tok.get("ownerId", "")
    ed_pub = tok.get("edPub", "")
    kem_pub = tok.get("kemPub", "")
    kem_sig = tok.get("kemSig", "")
    if not (
        isinstance(owner_id, str) and _USER_ID_HEX_RE.match(owner_id)
        and isinstance(ed_pub, str) and _ED_PUB_HEX_RE.match(ed_pub)
        and isinstance(kem_pub, str) and _KEM_PUB_HEX_RE.match(kem_pub)
        and isinstance(kem_sig, str) and _KEM_SIG_HEX_RE.match(kem_sig)
    ):
        return None
    return tok


def decode_identity_link(fragment: str) -> IdentityLink:
    """Decode + shape-check a ``#…`` fragment.

    Synchronous shape validation only — the ``ownerId ↔ edPub`` binding is
    verified asynchronously via :func:`verify_identity_link_binding`.
    Rejects v:1 links (callers must re-publish with v:2).

    Raises:
        ValueError: if the fragment is malformed or fails shape-check.
    """
    raw: dict[str, Any] = decode_link_fragment(fragment, _validate_identity_link, _MALFORMED)
    return IdentityLink(
        v=2,
        owner_id=raw["ownerId"],
        pseudo=raw.get("pseudo") or "",
        ed_pub=raw["edPub"],
        kem_pub=raw["kemPub"],
        kem_sig=raw["kemSig"],
    )


# ── Own identity link ─────────────────────────────────────────────────────────


async def my_identity_link(
    session: "Session",
    origin: str,
    path: str,
) -> Optional[str]:
    """Build this account's own identity link (derivable on any device).

    Returns ``None`` only if the profile keys have not been published yet.
    """
    # Root device: keys are already on the session — compute kemSig locally.
    if session.owner_ed_pub == session.keys["edPub"]:
        kem_sig = sign_kem_sig(session.keys["kemPub"], session.keys["edPriv"])
        return encode_identity_link(
            origin, path,
            IdentityLink(
                v=2,
                owner_id=session.user_id,
                pseudo=session.name,
                ed_pub=session.keys["edPub"],
                kem_pub=session.keys["kemPub"],
                kem_sig=kem_sig,
            ),
        )
    # Paired device: read published keys from the profile.
    from starfish_spaces.client import read_profile
    profile = await read_profile(session.account_client, session.user_id, session.layout)
    if not (profile.get("edPub") and profile.get("kemPub") and profile.get("kemSig")):
        return None
    return encode_identity_link(
        origin, path,
        IdentityLink(
            v=2,
            owner_id=session.user_id,
            pseudo=session.name,
            ed_pub=profile["edPub"],
            kem_pub=profile["kemPub"],
            kem_sig=profile["kemSig"],
        ),
    )


# ── Live cross-check ──────────────────────────────────────────────────────────


async def verify_identity_link_keys(
    token: IdentityLink,
    session: "Session",
) -> None:
    """Cross-check a decoded token against the owner's published profile.

    Throws if the profile has DIFFERENT keys than the token.
    Succeeds silently when the profile is unreachable.
    """
    from starfish_spaces.client import make_anon_space_client, ClientOpts

    try:
        from starfish_spaces.client import read_profile
        anon_opts: ClientOpts = {"baseUrl": session.base_url, "namespace": session.namespace}  # type: ignore[misc]
        anon_client = make_anon_space_client(anon_opts)
        profile = await read_profile(anon_client, token.owner_id, session.layout)
    except Exception:
        return  # unreachable — succeed silently

    if profile.get("edPub") and profile["edPub"] != token.ed_pub:
        raise ValueError("This identity link doesn't match the owner's published identity keys.")
    if profile.get("kemPub") and profile["kemPub"] != token.kem_pub:
        raise ValueError("This identity link doesn't match the owner's published identity keys.")


__all__ = [
    "IdentityLink",
    "verify_identity_link_binding",
    "encode_identity_link",
    "decode_identity_link",
    "my_identity_link",
    "verify_identity_link_keys",
]
