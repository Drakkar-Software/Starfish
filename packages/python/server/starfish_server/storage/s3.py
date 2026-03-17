"""S3-compatible object store implementation using aiobotocore."""


import asyncio
from dataclasses import dataclass
from typing import Any
from starfish_server.storage.base import AbstractObjectStore


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

    async def get_string(self, key: str) -> str | None:
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

    async def list_keys(
        self,
        prefix: str,
        *,
        start_after: str | None = None,
        limit: int | None = None,
    ) -> list[str]:
        client = await self._get_client()
        kwargs: dict[str, Any] = {
            "Bucket": self._opts.bucket,
            "Prefix": prefix,
        }
        if start_after:
            kwargs["StartAfter"] = start_after
        if limit:
            kwargs["MaxKeys"] = limit

        resp = await client.list_objects_v2(**kwargs)
        contents = resp.get("Contents", [])
        return [obj["Key"] for obj in contents]

    async def delete(self, key: str) -> None:
        client = await self._get_client()
        await client.delete_object(Bucket=self._opts.bucket, Key=key)

    async def delete_many(self, keys: list[str]) -> None:
        if not keys:
            return
        client = await self._get_client()
        await client.delete_objects(
            Bucket=self._opts.bucket,
            Delete={"Objects": [{"Key": k} for k in keys]},
        )
