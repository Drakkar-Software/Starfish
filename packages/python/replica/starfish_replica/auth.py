"""Replica-request signing client.

A replica node pulls/pushes against a primary Starfish server with authenticated,
per-request-signed HTTP calls. This module provides :class:`ReplicaAuth`, an
``httpx.Auth`` that an app injects into the ``httpx.AsyncClient`` it hands to
:class:`~starfish_replica.manager.ReplicaManager`:

    client = httpx.AsyncClient(timeout=30.0, auth=ReplicaAuth(passphrase="..."))
    manager = ReplicaManager(store, collections, client=client)

It is pure Starfish plumbing — no product/app logic. Per request it:

1. signs the canonical request bytes with
   :func:`starfish_protocol.request_signing.sign_request` and attaches the
   ``X-Starfish-Sig``/``-Ts``/``-Nonce`` headers, and
2. attaches an ``Authorization: Cap <base64(stable_stringify(cap))>`` header
   built from a self-signed device cap-cert.

The cap-cert has a finite TTL (``mint_device_cap`` defaults to 30 days). A
long-uptime replica would otherwise 401-storm once the cap expires, so the cap
is transparently re-minted when it nears expiry (see ``refresh_margin_sec``).
The signing key and the derived userId never change across a refresh, so the
identity (and any role the primary grants it) is preserved.

The hook is :py:meth:`auth_flow` (NOT ``sync_auth_flow``) so it applies to BOTH
:class:`httpx.Client` and :class:`httpx.AsyncClient`: httpx's default
``async_auth_flow`` defers to ``auth_flow``, while overriding ``sync_auth_flow``
alone would leave the async path shipping unsigned requests.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Callable, Generator
from typing import TYPE_CHECKING, Any, Optional

import httpx

from starfish_identities import bootstrap_root_identity, mint_device_cap, scopes
from starfish_protocol.constants import (
    HEADER_AUTHORIZATION,
    HEADER_NONCE,
    HEADER_SIG,
    HEADER_TS,
)
from starfish_protocol.hash import stable_stringify
from starfish_protocol.request_signing import sign_request

if TYPE_CHECKING:  # pragma: no cover - typing only
    from starfish_identities import DeviceCredentials, ScopePreset


# Re-mint when the current cap has less than this many seconds until exp. Default
# to a day so even a low-traffic replica refreshes well before the 30d TTL.
_DEFAULT_REFRESH_MARGIN_SEC = 24 * 3600


class ReplicaAuth(httpx.Auth):
    """``httpx.Auth`` that signs every replica request with a device cap-cert.

    Construct it with either a ``passphrase`` (the platform root identity is
    bootstrapped via :func:`starfish_identities.bootstrap_root_identity`) or a
    pre-bootstrapped ``credentials`` :class:`~starfish_identities.DeviceCredentials`
    (so an app that already holds the identity needn't re-derive it). Exactly one
    of the two must be supplied.

    :param passphrase: Passphrase to bootstrap the root identity from. Mutually
        exclusive with ``credentials``.
    :param credentials: A pre-bootstrapped :class:`DeviceCredentials`. Mutually
        exclusive with ``passphrase``.
    :param scope: Cap scope to re-mint with on refresh. Defaults to
        ``scopes.root_all()`` (read/list/write on every path + collection) —
        the access a replica needs for pull/push.
    :param refresh_margin_sec: Re-mint the cap when it has fewer than this many
        seconds left until expiry. Defaults to one day.
    :param clock: Injectable ``() -> int`` returning the current Unix time in
        seconds. Defaults to :func:`time.time`. Used by tests to exercise the
        auto-refresh path with a short-lived cap.
    """

    requires_request_body = True

    def __init__(
        self,
        *,
        passphrase: Optional[str] = None,
        credentials: "Optional[DeviceCredentials]" = None,
        scope: "Optional[ScopePreset]" = None,
        refresh_margin_sec: int = _DEFAULT_REFRESH_MARGIN_SEC,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if (passphrase is None) == (credentials is None):
            raise ValueError(
                "ReplicaAuth requires exactly one of 'passphrase' or 'credentials'"
            )
        creds = credentials if credentials is not None else bootstrap_root_identity(passphrase)  # type: ignore[arg-type]
        # Keep the bootstrap outputs so re-minting the cap on expiry needs no
        # further (expensive) key derivation.
        self._ed_priv: str = creds.device["edPriv"]
        self._ed_pub: str = creds.device["edPub"]
        self._kem_pub: str = creds.device["kemPub"]
        # Expose the derived userId so a caller can cross-check it against a
        # configured value and fail fast on a mis-paired identity.
        self.user_id: str = creds.user_id
        self._scope: dict[str, Any] = dict(scope) if scope is not None else dict(scopes.root_all())
        self._refresh_margin_sec = refresh_margin_sec
        self._clock = clock or time.time
        self._set_cap(creds.cap_cert)

    def _set_cap(self, cap: dict[str, Any]) -> None:
        """Cache a cap + its derived Authorization header + exp timestamp."""
        self._cap_exp: int = int(cap["exp"])
        cap_json = stable_stringify(cap)
        self._auth_header = "Cap " + base64.b64encode(
            cap_json.encode("utf-8")
        ).decode("ascii")

    def _refresh_cap_if_needed(self) -> None:
        """Re-mint the self-signed device cap when it's close to expiry. Same
        priv/pub keys → same userId → role is preserved across refresh.
        """
        if int(self._clock()) < self._cap_exp - self._refresh_margin_sec:
            return
        cap = mint_device_cap(
            self._ed_priv,
            self._ed_pub,
            {"edPubHex": self._ed_pub, "kemPubHex": self._kem_pub},
            self._scope,
        )
        self._set_cap(cap)

    def auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        # auth_flow (not sync_auth_flow) is the right hook for stateless signers:
        # httpx's default sync_auth_flow AND async_auth_flow both defer to it.
        self._refresh_cap_if_needed()
        body = bytes(request.content) if request.content else b""
        url = request.url
        # Mirror the server's path reconstruction (cap_resolver._path_and_query):
        # the server uses ASGI-decoded ``url.path`` + ``url.query``, NOT the
        # percent-encoded ``raw_path``. Build the same shape here so a path with
        # any reserved char survives round-trip without signature drift.
        path = url.path
        query = url.query.decode("ascii") if isinstance(url.query, bytes) else url.query
        path_and_query = f"{path}?{query}" if query else path
        # Match cap_resolver._host_from_request: full netloc (port included for
        # non-default ports). url.host drops the port, which would diverge from
        # the server's reconstruction when the primary listens on a non-default port.
        netloc = url.netloc
        host = netloc.decode("ascii") if isinstance(netloc, bytes) else netloc
        sig = sign_request(
            request.method,
            path_and_query,
            body,
            self._ed_priv,
            host=host,
        )
        request.headers[HEADER_AUTHORIZATION] = self._auth_header
        request.headers[HEADER_SIG] = sig.sig
        request.headers[HEADER_TS] = str(sig.ts)
        request.headers[HEADER_NONCE] = sig.nonce
        yield request


__all__ = ["ReplicaAuth"]
