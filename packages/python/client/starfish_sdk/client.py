"""Low-level HTTP client for the Starfish sync protocol."""

import base64
import json
from typing import Any

import httpx

from starfish_protocol.hash import stable_stringify
from starfish_protocol.request_signing import sign_request
from starfish_protocol.suites import DEFAULT_ALG
from starfish_protocol.types import PullKeyringProjection, PullResult, PushSuccess
from starfish_sdk.types import (
    BlobPullResult,
    BlobPushResult,
    CapProvider,
    ClientPlugin,
    ConflictError,
    StarfishHttpError,
)

APPEND_DEFAULT_FIELD = "items"

APPEND_DEFAULT_FIELD = "items"


class StarfishClient:
    """Low-level HTTP client for the Starfish sync protocol.

    Handles auth headers and response parsing.
    """

    def __init__(
        self,
        base_url: str,
        *,
        cap_provider: CapProvider | None = None,
        namespace: str | None = None,
        timeout: float = 30.0,
        client: httpx.AsyncClient | None = None,
        plugins: "list[ClientPlugin] | None" = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._cap_provider = cap_provider
        self._namespace = namespace
        self._client = client or httpx.AsyncClient(timeout=timeout)
        # Stored but no hooks fire yet. Extensions can inspect
        # ``client.plugins`` if needed; lifecycle callbacks may be added
        # later.
        self.plugins: tuple["ClientPlugin", ...] = tuple(plugins or [])

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> "StarfishClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    def _send_path(self, path: str) -> str:
        return self._sign_path(path)

    def _sign_path(self, path: str) -> str:
        if self._namespace is None:
            return path
        return f"/v1/{self._namespace}/{path[4:]}"

    def _signing_host(self) -> str:
        """Return the host portion of ``base_url`` for the request-signing bind.

        The ``h`` field on the canonical signing input pins a signature to a
        single Starfish server host. We parse ``base_url`` via ``httpx.URL``
        so the resulting host string matches what the server-side verifier
        reconstructs (``netloc`` drops default ports for known schemes, same
        as JS ``new URL().host``). Returns ``""`` when ``base_url`` is not
        parseable as an absolute URL.
        """
        try:
            netloc = httpx.URL(self._base_url).netloc
        except (httpx.InvalidURL, ValueError):
            return ""
        if isinstance(netloc, bytes):
            return netloc.decode("ascii")
        return netloc

    async def _auth_headers(
        self, method: str, path_and_query: str, body: str | None
    ) -> dict[str, str]:
        """Build auth headers for one outgoing request.

        When a ``cap_provider`` is set, signs the request with the device's
        Ed25519 private key and emits the v3 header set
        (``Authorization: Cap <…>``, ``X-Starfish-Sig``, ``X-Starfish-Ts``,
        ``X-Starfish-Nonce``). The signed body bytes MUST equal the bytes sent
        on the wire — callers pass the already-serialized body string here so
        signing and transmission agree. The host bound into the signature is
        derived from ``base_url`` so a captured request cannot be replayed
        against a different Starfish server. Returns an empty dict when no
        provider is configured (public-read collections).
        """
        if self._cap_provider is None:
            return {}
        ctx = await self._cap_provider.get_cap()
        cap = ctx["cap"]
        dev_ed_priv_hex = ctx["dev_ed_priv_hex"]
        body_bytes = body.encode("utf-8") if isinstance(body, str) else b""
        # The signing suite is the suite of whoever holds ``dev_ed_priv_hex``:
        # - device/member: the subject signs, so use the cert's subject suite.
        #   Tolerant-reader rule (matches the server resolver): an absent
        #   ``subAlg`` means "same suite as the issuer", so fall back to
        #   ``cap["issAlg"]``, not the global default.
        # - audience (public-link): the presenter is an arbitrary redeemer
        #   signing with their own key, unrelated to the cert's suites, so use
        #   ``presenter_alg`` (defaulting to ed25519). The server reads it back
        #   from ``X-Starfish-Alg`` for audience caps.
        # `is not None`, not `or`: an empty-string suite tag must pass through
        # unchanged (→ server rejects `X-Starfish-Alg: ""`), matching TS `??`.
        # `or` would coerce `""` → a default and forge a valid-looking request.
        if cap.get("kind") == "audience":
            presenter_alg = ctx.get("presenter_alg")
            sign_alg = presenter_alg if presenter_alg is not None else DEFAULT_ALG
        else:
            sub_alg = cap.get("subAlg")
            sign_alg = sub_alg if sub_alg is not None else cap.get("issAlg", DEFAULT_ALG)
        sig = sign_request(
            method,
            path_and_query,
            body_bytes,
            dev_ed_priv_hex,
            host=self._signing_host(),
            alg=sign_alg,
        )
        cap_b64 = base64.b64encode(
            stable_stringify(cap).encode("utf-8")
        ).decode("ascii")
        headers = {
            "Authorization": f"Cap {cap_b64}",
            "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": str(sig.ts),
            "X-Starfish-Nonce": sig.nonce,
            "X-Starfish-Alg": sig.alg,
        }
        # Audience (public-link) caps bind no single subject, so the server needs
        # the presenter's pubkey to verify the signature and check the allow-list.
        pub_hex = ctx.get("pub_hex")
        if pub_hex is not None:
            headers["X-Starfish-Pub"] = pub_hex
        return headers

    async def pull(
        self,
        path: str,
        checkpoint: int | None = None,
        *,
        append_field: str | None = None,
        since: int | None = None,
        last: int | None = None,
        with_keyring: bool = False,
    ) -> "PullResult | list[Any]":
        """Pull synced data from the server.

        Args:
            path: The pull endpoint path (e.g. "/pull/users/abc/settings")
            checkpoint: Only return data updated after this timestamp (0 = full pull)
            append_field: When set, extracts and returns ``data[append_field]`` as a
                list (append-only mode). Defaults to ``"items"`` when any append
                option is provided.
            since: Alias for ``checkpoint`` in append-only mode. Sent as
                ``?checkpoint=``. Ignored when ``append_field`` is not set.
            last: Return only the last K items after the checkpoint filter.
                Sent as ``?last=``. Ignored when ``append_field`` is not set.
            with_keyring: When True, appends ``?withKeyring=1`` to the request
                so the server includes the sibling ``<collection>/_keyring``
                document on the response. Saves a round-trip on cold start for
                delegated collections. The cap-cert scope MUST cover BOTH the
                data path AND ``<collection>/_keyring`` — ``scopes.writer(col)``
                denies the keyring path and will produce a 403; use
                ``scopes.read_write()`` or grant the keyring path explicitly
                when opting in. The returned ``PullResult.keyring`` is
                ``None`` when the server reports no keyring document exists.
        """
        params: dict[str, str] = {}

        if append_field is not None or since is not None or last is not None:
            field = append_field or APPEND_DEFAULT_FIELD
            if since is not None:
                if since < 0:
                    raise ValueError("since must be non-negative")
                params["checkpoint"] = str(since)
            if last is not None:
                if last < 0:
                    raise ValueError("last must be non-negative")
                params["last"] = str(last)
        else:
            field = None
            if checkpoint is not None and checkpoint > 0:
                params["checkpoint"] = str(checkpoint)

        if with_keyring:
            params["withKeyring"] = "1"

        # Build the canonical path-and-query for signing: when params are
        # present we serialize them into the path so the signed value matches
        # what the server sees on the wire. The cap-cert path uses the
        # URL-embedded form to avoid any mismatch with the signed canonical
        # input; the unauthenticated path falls back to httpx's ``params=``
        # encoder.
        signed_path = self._sign_path(path)
        if params:
            query = "&".join(f"{k}={v}" for k, v in params.items())
            signed_path_and_query = f"{signed_path}?{query}"
        else:
            signed_path_and_query = signed_path

        auth_headers = await self._auth_headers("GET", signed_path_and_query, None)

        if self._cap_provider is not None and params:
            # Send the pre-serialized query so the bytes on the wire match the
            # canonical input we just signed.
            url = f"{self._base_url}{self._send_path(path)}?" + "&".join(
                f"{k}={v}" for k, v in params.items()
            )
            resp = await self._client.get(
                url,
                headers={"Accept": "application/json", **auth_headers},
            )
        else:
            resp = await self._client.get(
                f"{self._base_url}{self._send_path(path)}",
                params=params,
                headers={"Accept": "application/json", **auth_headers},
            )
        if resp.status_code != 200:
            raise StarfishHttpError(resp.status_code, resp.text)

        body = resp.json()
        result = PullResult(
            data=body["data"],
            hash=body["hash"],
            timestamp=body["timestamp"],
            author_pubkey=body.get("authorPubkey"),
            author_signature=body.get("authorSignature"),
        )

        # ``keyring`` is present on the response only when the request set
        # ``?withKeyring=1``. ``None`` means the server reports no keyring
        # exists at ``<collection>/_keyring``; a dict means it was fetched
        # in the same round-trip. We preserve the absent/None/object
        # distinction by storing the projection (or ``None``) on the result.
        if "keyring" in body:
            kr = body["keyring"]
            if kr is None:
                # Use a marker object so callers can distinguish "asked, none"
                # from "didn't ask". We keep ``None`` on the dataclass because
                # the default is also ``None`` — callers needing the strict
                # distinction should check the with_keyring argument they
                # passed in.
                result.keyring = None
            elif isinstance(kr, dict):
                result.keyring = PullKeyringProjection(
                    data=kr.get("data", {}),
                    hash=kr.get("hash", ""),
                    timestamp=kr.get("timestamp", 0),
                )

        if field is not None:
            data = result.data if isinstance(result.data, dict) else {}
            arr = data.get(field)
            return arr if isinstance(arr, list) else []

        return result

    async def push(
        self,
        path: str,
        data: dict[str, Any],
        base_hash: str | None,
    ) -> PushSuccess:
        """Push synced data to the server.

        Args:
            path: The push endpoint path
            data: The full document data to push
            base_hash: Hash of the document this push is based on (None for first push)

        v3 author fields (``authorPubkey`` + ``authorSignature``) live inside
        ``data`` and are produced by :class:`SyncManager` when a ``signer``
        is configured.

        Raises:
            ConflictError: if the server detects a hash mismatch (409)
        """
        payload: dict[str, Any] = {"data": data, "baseHash": base_hash}
        body = json.dumps(payload)

        auth_headers = await self._auth_headers("POST", self._sign_path(path), body)

        resp = await self._client.post(
            f"{self._base_url}{self._send_path(path)}",
            content=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                **auth_headers,
            },
        )

        if resp.status_code == 409:
            raise ConflictError(resp.text)
        if resp.status_code != 200:
            raise StarfishHttpError(resp.status_code, resp.text)

        result = resp.json()
        return PushSuccess(hash=result["hash"], timestamp=result["timestamp"])

    async def append(
        self,
        path: str,
        data: dict[str, Any],
        ts: int | None = None,
    ) -> PushSuccess:
        """Append an element to an appendOnly (``by_timestamp``) collection.

        Unlike :meth:`push`, appendOnly writes carry no hash/conflict check — an
        authorized append is always accepted. Each element is stored server-side
        as ``{ts, data}`` and pulls can filter by ``ts`` via ``since``/``checkpoint``.

        Args:
            path: The push endpoint path (e.g. "/push/events")
            data: The element payload. For a ``delegated`` collection, encrypt it
                first; the server stores it opaquely and never reads it.
            ts: Optional client-supplied element timestamp (ms). Must be a
                non-negative integer strictly greater than the latest stored
                element's ts (else the server responds 409). Omit to let the
                server assign one.

        Raises:
            StarfishHttpError: on a non-2xx response (e.g. 409 for a
                non-monotonic timestamp).
        """
        payload: dict[str, Any] = {"data": data}
        if ts is not None:
            payload["ts"] = ts
        body = json.dumps(payload)

        auth_headers = await self._auth_headers("POST", self._sign_path(path), body)

        resp = await self._client.post(
            f"{self._base_url}{self._send_path(path)}",
            content=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                **auth_headers,
            },
        )

        if resp.status_code != 200:
            raise StarfishHttpError(resp.status_code, resp.text)

        result = resp.json()
        return PushSuccess(hash=result["hash"], timestamp=result["timestamp"])

    async def pull_blob(self, path: str) -> BlobPullResult:
        """Pull binary data from a blob collection.

        Returns raw bytes with the content hash from the ETag header.
        Binary collections use last-write-wins (no conflict detection).
        """
        auth_headers = await self._auth_headers("GET", self._sign_path(path), None)

        resp = await self._client.get(
            f"{self._base_url}{self._send_path(path)}",
            headers={"Accept": "*/*", **auth_headers},
        )
        if resp.status_code != 200:
            raise StarfishHttpError(resp.status_code, resp.text)

        etag = resp.headers.get("etag", "").strip('"') or None
        content_type = resp.headers.get("content-type", "application/octet-stream")
        return BlobPullResult(data=resp.content, hash=etag, content_type=content_type)

    async def push_blob(
        self,
        path: str,
        data: bytes,
        content_type: str,
    ) -> BlobPushResult:
        """Push binary data to a blob collection.

        Binary collections accept any push unconditionally (no baseHash required).
        """
        auth_headers = await self._auth_headers("POST", self._sign_path(path), None)

        resp = await self._client.post(
            f"{self._base_url}{self._send_path(path)}",
            content=data,
            headers={
                "Content-Type": content_type,
                "Accept": "application/json",
                **auth_headers,
            },
        )
        if resp.status_code != 200:
            raise StarfishHttpError(resp.status_code, resp.text)

        result = resp.json()
        return BlobPushResult(hash=result["hash"])

    async def get_config(self) -> dict:
        """Fetch the server's collection config from the /config endpoint."""
        config_path = "/sync/config" if self._namespace is not None else "/config"
        resp = await self._client.get(
            f"{self._base_url}{config_path}",
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            raise StarfishHttpError(resp.status_code, resp.text)
        return resp.json()
