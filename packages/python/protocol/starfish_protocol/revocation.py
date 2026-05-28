"""Build signed v3 revocation lists.

A ``RevocationList`` names ``(sub, nonce, exp)`` cap-cert tuples (and/or whole
``revokedSubjects``) revoked by an issuer's root identity. The list is
self-authenticating: it carries the issuer's Ed25519 signature over the
canonical serialization (``sig`` stripped) plus a monotonic ``generation``
counter, so a server can verify it without a cap and reject stale generations.
"""

from __future__ import annotations

import base64
from typing import Any

from starfish_protocol.cap import _user_id_from_pub_hex
from starfish_protocol.hash import stable_stringify
from starfish_protocol.suites import ed25519 as ed25519_suite


_REVOCATION_DOMAIN = "starfish-revlist-v1\n"


def revocation_list_canonical_signing_input(revocation_list: dict[str, Any]) -> str:
    """Canonical signing input for a revocation list."""
    unsigned = {k: v for k, v in revocation_list.items() if k != "sig"}
    return _REVOCATION_DOMAIN + stable_stringify(unsigned)


def build_revocation_list(
    iss_ed_pub_hex: str,
    iss_ed_priv_hex: str,
    generation: int,
    revoked: list[dict[str, Any]],
    revoked_subjects: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build and sign a ``RevocationList`` with the issuer's Ed25519 key."""
    unsigned: dict[str, Any] = {
        "v": 1,
        "iss": iss_ed_pub_hex,
        "issUserId": _user_id_from_pub_hex(iss_ed_pub_hex),
        "generation": generation,
        "revoked": revoked,
    }
    if revoked_subjects is not None:
        unsigned["revokedSubjects"] = revoked_subjects
    message = revocation_list_canonical_signing_input(unsigned).encode("utf-8")
    sig = base64.b64encode(ed25519_suite.sign(message, iss_ed_priv_hex)).decode("ascii")
    return {**unsigned, "sig": sig}
