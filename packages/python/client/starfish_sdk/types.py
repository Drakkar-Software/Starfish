"""Types for the Starfish client SDK."""


from dataclasses import dataclass
from typing import Any, Callable, Protocol

from starfish_protocol.types import PullResult, PushSuccess, Timestamps


@dataclass
class BlobPullResult:
    """Result of pulling a binary blob from the server."""

    data: bytes
    hash: str | None
    content_type: str


@dataclass
class BlobPushResult:
    """Result of pushing a binary blob to the server."""

    hash: str


class ConflictError(Exception):
    """Push conflict error (HTTP 409 — hash mismatch)."""

    def __init__(self, server_response: str = "") -> None:
        self.server_response = server_response
        super().__init__(f"hash_mismatch: {server_response}" if server_response else "hash_mismatch")


class StarfishHttpError(Exception):
    """HTTP error from the Starfish server."""

    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {body}")


class CapProvider(Protocol):
    """v3.0 cap-cert provider for :class:`StarfishClient`.

    ``get_cap()`` returns the device's cap-cert (as a dict) and the matching
    Ed25519 private key (hex). When configured on the client, every outgoing
    request carries ``Authorization: Cap <base64(stable_stringify(cap))>``
    plus ``X-Starfish-Sig`` / ``X-Starfish-Ts`` / ``X-Starfish-Nonce``.

    Implementations are expected to cache; the client may call this once
    per authenticated request.

    For an ``audience`` (public-link) cap, which binds no single subject, also
    return ``pub_hex`` — the redeemer's own Ed25519 pubkey matching
    ``dev_ed_priv_hex``. The client then sends it as ``X-Starfish-Pub`` so the
    server can verify the request signature against it and check the cap's
    ``aud`` allow-list. Omit ``pub_hex`` for device/member caps.
    """

    async def get_cap(self) -> dict[str, Any]:
        """Return ``{"cap": <CapCert dict>, "dev_ed_priv_hex": <str>}`` and,
        for audience caps, an optional ``"pub_hex": <str>``."""
        ...


ConflictResolver = Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]


@dataclass
class ClientPlugin:
    """Client-side plugin contract.

    A placeholder shape: the dataclass intentionally has no required
    hooks yet; extensions declare a plugin object with ``name`` and opt
    into specific lifecycle hooks once those exist. Apps wire plugins
    via ``StarfishClient(..., plugins=[...])``.

    Reserved for future hook fields. Hook additions are additive —
    extensions implementing a future hook will populate the relevant
    optional attribute without affecting existing zero-hook plugins.
    """

    name: str

