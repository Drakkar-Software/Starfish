"""S3-compatible object store implementation using aiobotocore."""


import asyncio
from dataclasses import dataclass
from typing import Any
from starfish_server.storage.base import AbstractObjectStore, StoreContext


@dataclass
class S3StorageOptions:
    """Configuration for the S3 object store."""

    access_key_id: str
    secret_access_key: str
    endpoint: str
    bucket: str
    region: str = "us-east-1"


class S3ObjectStore(AbstractObjectStore):
    """S3-compatible object store using aiobotocore."""

    def __init__(self, opts: S3StorageOptions) -> None:
        try:
            from aiobotocore.session import get_session
        except ImportError:
            raise ImportError(
                "aiobotocore is required for S3 storage. "
                "Install it with: pip install starfish-server[s3]"
            )
        self._session = get_session()
        self._opts = opts
        self._client_ctx: Any = None
        self._client: Any = None
        self._init_lock = asyncio.Lock()

    async def _get_client(self) -> Any:
        async with self._init_lock:
            if self._client is None:
                ctx = self._session.create_client(
                    "s3",
                    endpoint_url=self._opts.endpoint,
                    region_name=self._opts.region,
                    aws_access_key_id=self._opts.access_key_id,
                    aws_secret_access_key=self._opts.secret_access_key,
                )
                try:
                    self._client = await ctx.__aenter__()
                    self._client_ctx = ctx
                except BaseException:
                    self._client_ctx = None
                    raise
        return self._client

    async def close(self) -> None:
        """Close the underlying S3 client."""
        if self._client_ctx is not None:
            await self._client_ctx.__aexit__(None, None, None)
            self._client = None
            self._client_ctx = None

    async def get_string(self, key: str, *, context: StoreContext | None = None) -> str | None:  # noqa: ARG002
        client = await self._get_client()
        try:
            resp = await client.get_object(Bucket=self._opts.bucket, Key=key)
            body = await resp["Body"].read()
            return body.decode("utf-8")
        except client.exceptions.NoSuchKey:
            return None

    async def put(
        self,
        key: str,
        body: str,
        *,
        content_type: str | None = None,
        cache_control: str | None = None,
        context: StoreContext | None = None,  # noqa: ARG002
    ) -> None:
        client = await self._get_client()
        kwargs: dict[str, Any] = {
            "Bucket": self._opts.bucket,
            "Key": key,
            "Body": body.encode("utf-8"),
        }
        if content_type:
            kwargs["ContentType"] = content_type
        if cache_control:
            kwargs["CacheControl"] = cache_control
        await client.put_object(**kwargs)

    async def get_bytes(self, key: str, *, context: StoreContext | None = None) -> tuple[bytes, str] | None:  # noqa: ARG002
        client = await self._get_client()
        try:
            resp = await client.get_object(Bucket=self._opts.bucket, Key=key)
            body = await resp["Body"].read()
            content_type = resp.get("ContentType", "application/octet-stream")
            return body, content_type
        except client.exceptions.NoSuchKey:
            return None

    async def put_bytes(
        self,
        key: str,
        body: bytes,
        *,
        content_type: str,
        cache_control: str | None = None,
        context: StoreContext | None = None,  # noqa: ARG002
    ) -> None:
        client = await self._get_client()
        kwargs: dict[str, Any] = {
            "Bucket": self._opts.bucket,
            "Key": key,
            "Body": body,
            "ContentType": content_type,
        }
        if cache_control:
            kwargs["CacheControl"] = cache_control
        await client.put_object(**kwargs)

    async def list_keys(
        self,
        prefix: str,
        *,
        start_after: str | None = None,
        limit: int | None = None,
        context: StoreContext | None = None,  # noqa: ARG002
    ) -> list[str]:
        # S3 returns at most 1000 keys per page. Follow the continuation token
        # so the full key set is returned — the segmented append-only log keys
        # ALL chunks of a single document via ``list_keys`` (no ``limit``), so a
        # truncated first page would silently drop every chunk past the 1000th
        # and the checkpoint bisect would read incomplete data. With a ``limit``
        # we stop as soon as it is satisfied. (``StartAfter`` is honored only on
        # the first request; the continuation token governs subsequent pages.)
        client = await self._get_client()
        keys: list[str] = []
        continuation_token: str | None = None
        while True:
            kwargs: dict[str, Any] = {
                "Bucket": self._opts.bucket,
                "Prefix": prefix,
            }
            if continuation_token is None and start_after:
                kwargs["StartAfter"] = start_after
            if limit:
                kwargs["MaxKeys"] = limit
            if continuation_token is not None:
                kwargs["ContinuationToken"] = continuation_token

            resp = await client.list_objects_v2(**kwargs)
            for obj in resp.get("Contents", []):
                keys.append(obj["Key"])
            if limit and len(keys) >= limit:
                return keys[:limit]
            if not resp.get("IsTruncated"):
                return keys
            continuation_token = resp.get("NextContinuationToken")
            if continuation_token is None:
                return keys

    async def delete(self, key: str, *, context: StoreContext | None = None) -> None:  # noqa: ARG002
        client = await self._get_client()
        await client.delete_object(Bucket=self._opts.bucket, Key=key)

    async def delete_many(self, keys: list[str], *, context: StoreContext | None = None) -> None:  # noqa: ARG002
        if not keys:
            return
        client = await self._get_client()
        await client.delete_objects(
            Bucket=self._opts.bucket,
            Delete={"Objects": [{"Key": k} for k in keys]},
        )
