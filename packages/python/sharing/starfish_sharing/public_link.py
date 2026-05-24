"""Public-link API for plaintext (cap-only) sharing — Python mirror of
``public-link.ts``.

A public link is an ``audience`` cap-cert packed into a URL ``#fragment``.
Unlike a ``member`` cap it binds **no** single subject: every redeemer signs
requests with their **own** identity key (named via the ``X-Starfish-Pub``
header), so writes are attributable per user. An optional allow-list
(``allowed_identities``) narrows who may redeem; when omitted, any identity may.
No private key is ever embedded in the link.

``parse_public_link`` shape-checks the embedded cap but does NOT verify its
signature or expiry — that is the server's job at request time.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Optional

from starfish_protocol.hash import stable_stringify
from starfish_protocol.request_signing import sign_request

from .cap_mint import AudienceMintOpts, ScopePreset, assert_audience_cap_shape, mint_audience_cap

# Current public-link payload version.
_PUBLIC_LINK_V = 1


@dataclass
class PublicLink:
    """Result of :func:`create_public_link`."""

    # base64url payload to place after the ``#`` in a share URL.
    fragment: str
    # The minted audience cap-cert (also embedded in ``fragment``).
    cap: dict[str, Any]


@dataclass
class ParsedPublicLink:
    """Result of :func:`parse_public_link`."""

    cap: dict[str, Any]


# ── base64url (URL-fragment-safe) ───────────────────────────────────────────────
# Standard base64 (``+``, ``/``, ``=``) is unsafe in a URL fragment; map to
# base64url and strip padding. The exact same mapping is mirrored byte-for-byte
# in the TS ``public-link.ts``.


def _b64url_encode(s: str) -> str:
    std = base64.urlsafe_b64encode(s.encode("utf-8")).decode("ascii")
    return std.rstrip("=")


def _b64url_decode(s: str) -> str:
    rem = len(s) % 4
    if rem == 2:
        s += "=="
    elif rem == 3:
        s += "="
    elif rem == 1:
        raise ValueError("malformed public link: bad base64url length")
    return base64.urlsafe_b64decode(s.encode("ascii")).decode("utf-8")


def _encode_cap_auth(cap: dict[str, Any]) -> str:
    """Encode a cap-cert for the ``Authorization: Cap <…>`` header (matches the resolver)."""
    return base64.b64encode(stable_stringify(cap).encode("utf-8")).decode("ascii")


def create_public_link(
    iss_ed_priv_hex: str,
    iss_ed_pub_hex: str,
    collection: str,
    scope: ScopePreset | dict[str, Any],
    *,
    allowed_identities: Optional[list[str]] = None,
    expires_at: Optional[int] = None,
    ttl_sec: Optional[int] = None,
    nbf: Optional[int] = None,
    nonce: Optional[bytes] = None,
) -> PublicLink:
    """Mint an audience cap and pack it into a shareable URL fragment.

    With ``allowed_identities`` the link works only for those identities;
    without it, any identity may redeem. Either way the link carries no private
    key.
    """
    cap = mint_audience_cap(
        iss_ed_priv_hex,
        iss_ed_pub_hex,
        collection,
        scope,
        AudienceMintOpts(
            audience=allowed_identities,
            expires_at=expires_at,
            ttl_sec=ttl_sec,
            nbf=nbf,
            nonce=nonce,
        ),
    )
    payload = {"v": _PUBLIC_LINK_V, "cap": cap}
    fragment = _b64url_encode(stable_stringify(payload))
    return PublicLink(fragment=fragment, cap=cap)


def parse_public_link(fragment: str) -> ParsedPublicLink:
    """Decode and shape-check a public-link fragment.

    Does NOT verify the cap's signature or expiry — the server does that at
    request time. Raises :class:`ValueError` on a malformed fragment, wrong
    payload version, or a non-audience / malformed cap.
    """
    try:
        payload = json.loads(_b64url_decode(fragment.strip()))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("malformed public link: invalid fragment encoding") from exc
    if not isinstance(payload, dict):
        raise ValueError("malformed public link: payload is not an object")
    if payload.get("v") != _PUBLIC_LINK_V:
        raise ValueError(f"unsupported public link version: {payload.get('v')}")
    cap = payload.get("cap")
    if not isinstance(cap, dict) or cap.get("kind") != "audience":
        raise ValueError("malformed public link: cap is not an audience cap")
    # Structural validation only (no signature/expiry check — server's job).
    assert_audience_cap_shape(cap)
    return ParsedPublicLink(cap=cap)


def redeem_public_link(
    parsed: ParsedPublicLink,
    *,
    redeemer_ed_priv_hex: str,
    redeemer_ed_pub_hex: str,
    method: str,
    path_and_query: str,
    body: bytes | str = b"",
    host: Optional[str] = None,
    ts: Optional[int] = None,
    nonce: Optional[bytes] = None,
) -> dict[str, str]:
    """Build the header set a redeemer sends with each request, signing with the
    redeemer's own key and naming it via ``X-Starfish-Pub``.

    Transport-agnostic: the caller attaches these headers to its HTTP request.
    The body passed here MUST equal the bytes sent on the wire so the signature
    the server reconstructs matches.
    """
    body_bytes = body.encode("utf-8") if isinstance(body, str) else body
    signature = sign_request(
        method,
        path_and_query,
        body_bytes,
        redeemer_ed_priv_hex,
        host=host,
        ts=ts,
        nonce=nonce,
    )
    return {
        "Authorization": f"Cap {_encode_cap_auth(parsed.cap)}",
        "X-Starfish-Sig": signature.sig,
        "X-Starfish-Ts": str(signature.ts),
        "X-Starfish-Nonce": signature.nonce,
        "X-Starfish-Pub": redeemer_ed_pub_hex,
    }


__all__ = [
    "PublicLink",
    "ParsedPublicLink",
    "create_public_link",
    "parse_public_link",
    "redeem_public_link",
]
