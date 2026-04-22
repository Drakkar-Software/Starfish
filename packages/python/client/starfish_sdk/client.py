"""Low-level HTTP client for the Starfish sync protocol."""

import json
from typing import Any

import httpx

from starfish_protocol.types import PullResult, PushSuccess
from starfish_sdk.types import AuthProvider, BlobPullResult, BlobPushResult, ConflictError, StarfishHttpError


class StarfishClient:
    """Low-level HTTP client for the Starfish sync protocol.

    Handles auth headers and response parsing.
    """

    def __init__(
        self,
        base_url: str,
        *,
        auth: AuthProvider | None = None,
        namespace: str | None = None,
        timeout: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = auth
        self._namespace = namespace
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> "StarfishClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    def _send_path(self, path: str) -> str:
        if self._namespace is None:
            return path
        return f"/sync/{self._namespace}{path}"

    def _sign_path(self, path: str) -> str:
        if self._namespace is None:
            return path
        return f"/v1/{self._namespace}/{path[4:]}"

    async def _auth_headers(
        self, method: str, path: str, body: str | None
    ) -> dict[str, str]:
        if self._auth is None:
            return {}
        return await self._auth(method=method, path=path, body=body)

    async def pull(self, path: str, checkpoint: int | None = None) -> PullResult:
        """Pull synced data from the server.

        Args:
            path: The pull endpoint path (e.g. "/pull/users/abc/settings")
            checkpoint: Only return data updated after this timestamp (0 = full pull)
        """
        params: dict[str, str] = {}
        if checkpoint is not None and checkpoint > 0:
            params["checkpoint"] = str(checkpoint)

        auth_headers = await self._auth_headers("GET", self._sign_path(path), None)

        resp = await self._client.get(
            f"{self._base_url}{self._send_path(path)}",
            params=params,
            headers={"Accept": "application/json", **auth_headers},
        )
        if resp.status_code != 200:
            raise StarfishHttpError(resp.status_code, resp.text)

        body = resp.json()
        return PullResult(
            data=body["data"],
            hash=body["hash"],
            timestamp=body["timestamp"],
            author_pubkey=body.get("authorPubkey"),
            author_signature=body.get("authorSignature"),
        )

    async def push(
        self,
        path: str,
        data: dict[str, Any],
        base_hash: str | None,
        author_signature: str | None = None,
    ) -> PushSuccess:
        """Push synced data to the server.

        Args:
            path: The push endpoint path
            data: The full document data to push
            base_hash: Hash of the document this push is based on (None for first push)
            author_signature: Optional author signature for provenance

        Raises:
            ConflictError: if the server detects a hash mismatch (409)
        """
        payload: dict[str, Any] = {"data": data, "baseHash": base_hash}
        if author_signature is not None:
            payload["authorSignature"] = author_signature
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
