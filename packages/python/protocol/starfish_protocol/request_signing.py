"""Per-request signing (v3.0).

Each authenticated HTTP request carries an Ed25519 signature over a canonical
encoding of (method, pathAndQuery, sha256(body), host, ts, nonce). The
canonical input is identical byte-for-byte across TypeScript and Python — see
``tests/test-vectors/request-signature.json`` for locked cases.

The ``host`` field binds a signature to one specific server host. Without
it, a signed request could be replayed against a different Starfish server
that shares no nonce cache with the original target.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Literal, Optional, TypedDict, Union

try:
    from typing import NotRequired
except ImportError:  # pragma: no cover
    from typing_extensions import NotRequired  # type: ignore[assignment]

from starfish_protocol.hash import stable_stringify
from starfish_protocol.suites import ed25519 as ed25519_suite


DEFAULT_MAX_SKEW_MS = 300_000


SignableMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]


class SignableRequest(TypedDict):
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


_REQUEST_SIG_DOMAIN = "starfish-req-v1\n"


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

    Definition: ``stable_stringify({m, p, b: sha256hex(body), h, ts, nonce})``.
    """
    body_hash = hashlib.sha256(body).hexdigest()
    return _REQUEST_SIG_DOMAIN + stable_stringify(
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
    dev_priv_hex: str,
    *,
    host: Optional[str] = None,
    ts: Optional[int] = None,
    nonce: Optional[bytes] = None,
) -> RequestSignature:
    """Produce an Ed25519 signature over the canonical request input."""
    if ts is None:
        ts = int(time.time() * 1000)
    if nonce is None:
        nonce = secrets.token_bytes(16)
    nonce_b64 = base64.b64encode(nonce).decode("ascii")
    canon = request_signing_canonical_input(
        method, path_and_query, body, ts, nonce_b64, host=host
    )
    sig_bytes = ed25519_suite.sign(canon.encode("utf-8"), dev_priv_hex)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
    return RequestSignature(sig=sig_b64, ts=ts, nonce=nonce_b64)


def verify_request_signature(
    method: str,
    path_and_query: str,
    body: bytes,
    signature: RequestSignature,
    signer_pub_hex: str,
    *,
    host: Optional[str] = None,
) -> bool:
    """Verify a request signature against a signer's Ed25519 public key."""
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
        return ed25519_suite.verify(sig_bytes, canon.encode("utf-8"), signer_pub_hex)
    except Exception:
        return False


def is_within_clock_skew(
    req_ts: int,
    now_ms: int,
    max_skew_ms: int = DEFAULT_MAX_SKEW_MS,
) -> bool:
    """Return ``True`` iff ``|req_ts - now_ms| <= max_skew_ms``."""
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
