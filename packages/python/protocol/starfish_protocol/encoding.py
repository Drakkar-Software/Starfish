"""URL-safe Base64 and link-fragment utilities.

Mirrors ``packages/ts/protocol/src/encoding.ts``.

- :func:`to_base64url` / :func:`from_base64url` — UTF-8 string ↔ base64url
  (no ``=`` padding, ``+/`` → ``-_``).
- :func:`encode_link_fragment` / :func:`decode_link_fragment` — pack/unpack a
  JSON token into a URL fragment with the origin stripped from the path.
"""

import base64
import json
from typing import Any, Callable, TypeVar

T = TypeVar("T")


def to_base64url(json_str: str) -> str:
    """Encode a UTF-8 string to base64url (URL-safe base64, no ``=`` padding)."""
    encoded = base64.b64encode(json_str.encode("utf-8")).decode("ascii")
    return encoded.replace("+", "-").replace("/", "_").rstrip("=")


def from_base64url(b64url: str) -> str:
    """Decode a base64url string back to a UTF-8 string.

    Tolerant of missing ``=`` padding and either ``+/`` or ``-_`` alphabet.
    """
    b64 = b64url.replace("-", "+").replace("_", "/")
    # Re-add padding so Python's base64 decoder is happy.
    pad = (4 - len(b64) % 4) % 4
    b64 += "=" * pad
    return base64.b64decode(b64).decode("utf-8")


def encode_link_fragment(origin: str, path: str, token: Any) -> str:
    """Pack *token* into a shareable URL with the origin stripped from *path*.

    The token is JSON-serialised and base64url-encoded into the URL fragment::

        https://app.example.com/join#eyJ0eXBlIjoic3BhY2UiLCJpZCI6Ii4uLiJ9

    Args:
        origin: e.g. ``"https://app.example.com"`` — trailing slashes stripped.
        path:   e.g. ``"/join"`` or ``"join"``.
        token:  Any JSON-serialisable value to encode in the fragment.
    """
    base = origin.rstrip("/")
    p = path.lstrip("/")
    fragment = to_base64url(json.dumps([origin, path, token], separators=(",", ":")))
    return f"{base}/{p}#{fragment}"


def decode_link_fragment(
    fragment: str,
    validate: Callable[[Any], T],
    err_msg: str = "invalid link fragment",
) -> T:
    """Decode a link fragment previously produced by :func:`encode_link_fragment`.

    Args:
        fragment: The raw fragment string — either the full ``#…`` hash (``#``
                  is stripped automatically) or just the base64url payload.
        validate: Callable that receives the parsed token and either returns the
                  typed value or raises :class:`ValueError` on a shape mismatch.
        err_msg:  Message raised when parsing or validation fails.

    Raises:
        ValueError: when the fragment is malformed or *validate* raises.
    """
    raw = fragment[1:] if fragment.startswith("#") else fragment
    try:
        parsed = json.loads(from_base64url(raw))
    except Exception:
        raise ValueError(err_msg)
    # Canonical form is [origin, path, token]; recover the token before
    # validating. A bare (non-array) payload is tolerated for resilience against
    # older single-value fragments.
    token = parsed[2] if isinstance(parsed, list) and len(parsed) >= 3 else parsed
    try:
        result = validate(token)
    except Exception:
        raise ValueError(err_msg)
    # A validator that returns ``None``/falsy signals a shape mismatch (the TS
    # null-return convention); reject it identically instead of returning None.
    if result is None:
        raise ValueError(err_msg)
    return result
