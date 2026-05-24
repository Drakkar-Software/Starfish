"""Per-request Ed25519 signing (v3.0).

Each authenticated HTTP request carries an Ed25519 signature over a
canonical encoding of (method, pathAndQuery, sha256(body), host, ts, nonce).
The canonical input is identical byte-for-byte across TypeScript and
Python — see ``tests/test-vectors/request-signature.json`` for locked
cases.

The ``host`` field binds a signature to one specific server host. Without
it, an Ed25519-signed request could be replayed against a different
Starfish server that shares no nonce cache with the original target. The
field is always present in the canonical input — it is the empty string
``""`` when the caller omits ``host`` — so an attacker cannot bypass the
bind by leaving the field off.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Literal, Optional, TypedDict, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

try:
    from typing import NotRequired
except ImportError:  # pragma: no cover - safety net for older runtimes
    from typing_extensions import NotRequired  # type: ignore[assignment]

from starfish_protocol.hash import stable_stringify


DEFAULT_MAX_SKEW_MS = 300_000


SignableMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
"""HTTP methods the request-signing protocol supports."""


class SignableRequest(TypedDict):
    """Minimal request shape used as input to the signature.

    The optional ``host`` field is folded into the canonical input as the
    ``h`` key; an absent value is encoded as ``h: ""``. The host binds a
    signature to one specific server (e.g. ``"api.example.com"``) so an
    intercepted request cannot be replayed against a different Starfish
    server that shares no nonce cache.
    """

    method: SignableMethod
    pathAndQuery: str
    body: NotRequired[Union[bytes, str]]
    host: NotRequired[str]


@dataclass(frozen=True)
class RequestSignature:
    """Signature bundle attached to an outbound request."""

    sig: str
    """Base64-encoded Ed25519 signature."""

    ts: int
    """Unix milliseconds; included verbatim in the canonical input."""

    nonce: str
    """Standard (with padding) base64 of a random 16-byte nonce."""


def request_signing_canonical_input(
    method: str,
    path_and_query: str,
    body: bytes,
    ts: int,
    nonce_b64: str,
    *,
    host: Optional[str] = None,
) -> str:
    """Canonical UTF-8 string used as the Ed25519 signing input.

    Definition:
    ``stable_stringify({m, p, b: sha256hex(body), h, ts, nonce})``.
    ``b`` is the lowercase hex SHA-256 of the request body bytes; an empty
    body yields the SHA-256 of an empty buffer
    (``e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855``).
    ``h`` is ``host`` or ``""`` when omitted — it is ALWAYS present so a
    client cannot bypass the host bind by skipping the field. ``nonce`` is
    the same base64 string included on the returned signature.
    """
    body_hash = hashlib.sha256(body).hexdigest()
    return stable_stringify(
        {
            "m": method,
            "p": path_and_query,
            "b": body_hash,
            "h": host or "",
            "ts": ts,
            "nonce": nonce_b64,
        }
    )


def sign_request(
    method: str,
    path_and_query: str,
    body: bytes,
    dev_ed_priv_hex: str,
    *,
    host: Optional[str] = None,
    ts: Optional[int] = None,
    nonce: Optional[bytes] = None,
) -> RequestSignature:
    """Produce an Ed25519 signature over the canonical request input.

    Defaults: ``ts`` is ``int(time.time() * 1000)``; ``nonce`` is 16
    random bytes from :func:`secrets.token_bytes`. The returned
    ``nonce`` field is the same base64 string used inside the canonical
    signing input.

    ``host`` is keyword-only and optional; when supplied, it is folded
    into the canonical input as the ``h`` field. Verifiers must pass the
    same ``host`` value reconstructed from the inbound request URL.
    """
    if ts is None:
        ts = int(time.time() * 1000)
    if nonce is None:
        nonce = secrets.token_bytes(16)
    nonce_b64 = base64.b64encode(nonce).decode("ascii")
    canon = request_signing_canonical_input(
        method, path_and_query, body, ts, nonce_b64, host=host
    )
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(dev_ed_priv_hex))
    sig_bytes = priv.sign(canon.encode("utf-8"))
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
    return RequestSignature(sig=sig_b64, ts=ts, nonce=nonce_b64)


def verify_request_signature(
    method: str,
    path_and_query: str,
    body: bytes,
    signature: RequestSignature,
    signer_ed_pub_hex: str,
    *,
    host: Optional[str] = None,
) -> bool:
    """Verify a request signature against a signer's Ed25519 public key.

    The ``signature.nonce`` and ``signature.ts`` are folded into the
    canonical input exactly as on the signing side; tampered fields fail
    verification. ``host`` is keyword-only and optional; pass the host
    reconstructed from the inbound request URL — the verify fails if it
    does not match what the client signed. Returns ``False`` on any
    cryptographic or decoding error.
    """
    try:
        canon = request_signing_canonical_input(
            method,
            path_and_query,
            body,
            signature.ts,
            signature.nonce,
            host=host,
        )
        sig_bytes = base64.b64decode(signature.sig)
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer_ed_pub_hex))
        pub.verify(sig_bytes, canon.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def is_within_clock_skew(
    req_ts: int,
    now_ms: int,
    max_skew_ms: int = DEFAULT_MAX_SKEW_MS,
) -> bool:
    """Return ``True`` iff ``|req_ts - now_ms| <= max_skew_ms``.

    Default skew is 5 minutes (``300_000`` ms).
    """
    return abs(req_ts - now_ms) <= max_skew_ms


__all__ = [
    "RequestSignature",
    "SignableMethod",
    "SignableRequest",
    "request_signing_canonical_input",
    "sign_request",
    "verify_request_signature",
    "is_within_clock_skew",
]
