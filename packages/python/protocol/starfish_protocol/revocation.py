"""Build signed v3 revocation lists.

A ``RevocationList`` names ``(sub, nonce, exp)`` cap-cert tuples (and/or whole
``revokedSubjects``) revoked by an issuer's root identity. The list is
self-authenticating: it carries the issuer's Ed25519 signature over the canonical
serialization (``sig`` stripped) plus a monotonic ``generation`` counter, so a
server can verify it without a cap and reject stale generations.

This is the reusable builder the SDKs and apps were previously forced to hand-roll
(the example chat app signed lists inline). It mirrors the TypeScript
``buildRevocationList`` byte-for-byte — guarded by the shared
``tests/test-vectors/revocation-list.json`` conformance vector.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from starfish_protocol.cap import _user_id_from_pub_hex
from starfish_protocol.hash import stable_stringify


def revocation_list_canonical_signing_input(revocation_list: dict[str, Any]) -> str:
    """Canonical signing input for a revocation list: stable JSON with ``sig`` stripped.

    Byte-for-byte identical to the TS ``revocationListCanonicalSigningInput``.
    """
    unsigned = {k: v for k, v in revocation_list.items() if k != "sig"}
    return stable_stringify(unsigned)


def build_revocation_list(
    iss_ed_pub_hex: str,
    iss_ed_priv_hex: str,
    generation: int,
    revoked: list[dict[str, Any]],
    revoked_subjects: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build and sign a ``RevocationList``.

    ``revoked`` is a list of ``{"sub", "nonce", "exp"}`` tuples; ``revoked_subjects``
    (optional) is a list of ``{"sub", "exp"}`` entries revoking every cap with that
    subject. ``issUserId`` is derived as ``sha256(iss_ed_pub)[:32]``. The returned
    dict adds a base64 (standard, padded) ``sig`` over the canonical signing input.
    """
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
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(iss_ed_priv_hex))
    sig = base64.b64encode(priv.sign(message)).decode("ascii")
    return {**unsigned, "sig": sig}
