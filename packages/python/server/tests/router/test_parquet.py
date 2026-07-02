"""Tests for the Parquet / DuckDB collection helpers."""

import hashlib

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_protocol.constants import PARQUET_MIME_TYPE, PARQUET_MIME_TYPES
from starfish_server import (
    create_parquet_collection,
    create_sealed_parquet_collection,
    duckdb_read_parquet_sql,
    resolve_document_key,
    PARQUET_MIME_TYPE as SERVER_PARQUET_MIME_TYPE,
    PARQUET_MIME_TYPES as SERVER_PARQUET_MIME_TYPES,
)
from starfish_server.config.schema import SyncConfig, CollectionRateLimitConfig
from starfish_server.config.validate import validate_config
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from starfish_server.storage.s3 import S3StorageOptions
from tests.helpers import MemoryObjectStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Parquet magic bytes (PAR1 header + footer)
PARQUET_BYTES = b"PAR1" + b"\x00" * 100 + b"PAR1"


def _build_app(col=None):
    if col is None:
        col = create_parquet_collection(
            name="datasets",
            storage_path="datasets/{owner}/{file}",
        )
    store = MemoryObjectStore()
    config = SyncConfig(version=1, collections=[col])

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["public", "cap:write:datasets"])

    router = create_sync_router(SyncRouterOptions(store=store, config=config, role_resolver=role_resolver))
    app = FastAPI()
    app.include_router(router)
    return app, store


# ---------------------------------------------------------------------------
# MIME constants
# ---------------------------------------------------------------------------


class TestParquetMimeConstants:
    def test_canonical_mime_type(self):
        assert PARQUET_MIME_TYPE == "application/vnd.apache.parquet"

    def test_server_re_exports_match_protocol(self):
        assert SERVER_PARQUET_MIME_TYPE == PARQUET_MIME_TYPE
        assert tuple(SERVER_PARQUET_MIME_TYPES) == tuple(PARQUET_MIME_TYPES)

    def test_mime_types_includes_all_variants(self):
        assert "application/vnd.apache.parquet" in PARQUET_MIME_TYPES
        assert "application/x-parquet" in PARQUET_MIME_TYPES
        assert "application/octet-stream" in PARQUET_MIME_TYPES


# ---------------------------------------------------------------------------
# resolve_document_key
# ---------------------------------------------------------------------------


class TestResolveDocumentKey:
    def test_single_param(self):
        assert resolve_document_key("users/{identity}/notes", {"identity": "alice"}) == "users/alice/notes"

    def test_multiple_params(self):
        result = resolve_document_key(
            "datasets/{owner}/{dataset}", {"owner": "alice", "dataset": "q1.parquet"}
        )
        assert result == "datasets/alice/q1.parquet"

    def test_unknown_param_left_as_is(self):
        assert resolve_document_key("datasets/{owner}/{dataset}", {"owner": "alice"}) == "datasets/alice/{dataset}"


# ---------------------------------------------------------------------------
# create_parquet_collection — config factory
# ---------------------------------------------------------------------------


class TestCreateParquetCollection:
    def test_defaults(self):
        col = create_parquet_collection(name="datasets", storage_path="datasets/{owner}/{file}")
        assert col.name == "datasets"
        assert col.read_roles == ["public"]
        assert col.write_roles == ["cap:write:datasets"]
        assert col.encryption == "none"
        assert col.max_body_bytes == 256 * 1024 * 1024
        assert col.allowed_mime_types == list(PARQUET_MIME_TYPES)
        assert col.rate_limit is None

    def test_forces_encryption_none(self):
        col = create_parquet_collection(name="x", storage_path="x/{id}")
        assert col.encryption == "none"

    def test_read_public(self):
        col = create_parquet_collection(name="x", storage_path="x/{id}", read="public", write="authenticated")
        assert col.read_roles == ["public"]
        assert col.push_only is None

    def test_read_authenticated(self):
        col = create_parquet_collection(name="x", storage_path="x/{id}", read="authenticated", write="public")
        assert col.read_roles == ["cap:read:x"]

    def test_read_none_sets_push_only(self):
        col = create_parquet_collection(name="x", storage_path="x/{id}", read="none", write="public")
        assert col.push_only is True
        assert col.pull_only is None

    def test_write_public(self):
        col = create_parquet_collection(name="x", storage_path="x/{id}", read="public", write="public")
        assert col.write_roles == ["public"]

    def test_write_authenticated(self):
        col = create_parquet_collection(name="x", storage_path="x/{id}", read="public", write="authenticated")
        assert col.write_roles == ["cap:write:x"]

    def test_write_none_sets_pull_only(self):
        col = create_parquet_collection(name="x", storage_path="x/{id}", read="public", write="none")
        assert col.pull_only is True
        assert col.push_only is None

    def test_custom_role_list(self):
        col = create_parquet_collection(
            name="x",
            storage_path="x/{id}",
            read=["admin", "viewer"],
            write=["admin"],
        )
        assert col.read_roles == ["admin", "viewer"]
        assert col.write_roles == ["admin"]

    def test_raises_when_both_none(self):
        with pytest.raises(ValueError, match='both read and write are "none"'):
            create_parquet_collection(name="x", storage_path="x/{id}", read="none", write="none")

    def test_auto_listable_when_last_segment_is_param(self):
        col = create_parquet_collection(name="x", storage_path="datasets/{owner}/{file}")
        assert col.listable is True

    def test_no_listable_when_last_segment_is_literal(self):
        col = create_parquet_collection(name="x", storage_path="datasets/{owner}/summary")
        assert not col.listable

    def test_rate_limit_none_resolves_to_null(self):
        col = create_parquet_collection(name="x", storage_path="x/{id}", rate_limit="none")
        assert col.rate_limit is None

    def test_rate_limit_config_forwarded(self):
        rl = CollectionRateLimitConfig(windowMs=60_000, maxRequests=10)
        col = create_parquet_collection(name="x", storage_path="x/{id}", rate_limit=rl)
        assert col.rate_limit == rl

    def test_cache_duration_forwarded(self):
        col = create_parquet_collection(name="x", storage_path="x/{id}", cache_duration_ms=30_000)
        assert col.cache_duration_ms == 30_000

    def test_max_body_bytes_override(self):
        col = create_parquet_collection(name="x", storage_path="x/{id}", max_body_bytes=1024)
        assert col.max_body_bytes == 1024

    def test_passes_validate_config(self):
        col = create_parquet_collection(name="datasets", storage_path="datasets/{owner}/{file}")
        errors = validate_config(SyncConfig(version=1, collections=[col]))
        assert errors == []

    def test_read_none_passes_validate_config(self):
        col = create_parquet_collection(
            name="ingest",
            storage_path="ingest/{owner}/{file}",
            read="none",
            write="authenticated",
        )
        errors = validate_config(SyncConfig(version=1, collections=[col]))
        assert errors == []


# ---------------------------------------------------------------------------
# duckdb_read_parquet_sql
# ---------------------------------------------------------------------------

S3_MINIO = S3StorageOptions(
    endpoint="http://localhost:9000",
    bucket="my-bucket",
    access_key_id="minio",
    secret_access_key="minio123",
    region="us-east-1",
)

S3_AWS = S3StorageOptions(
    endpoint="https://s3.amazonaws.com",
    bucket="prod-bucket",
    access_key_id="AKID",
    secret_access_key="secret",
    region="eu-west-1",
)


class TestDuckdbReadParquetSql:
    def test_uri_for_minio(self):
        result = duckdb_read_parquet_sql(s3=S3_MINIO, key="datasets/alice/q1.parquet")
        assert result.uri == "s3://my-bucket/datasets/alice/q1.parquet"

    def test_setup_sql_contains_httpfs(self):
        result = duckdb_read_parquet_sql(s3=S3_MINIO, key="k")
        assert "INSTALL httpfs" in result.setup_sql
        assert "LOAD httpfs" in result.setup_sql

    def test_config_sql_minio(self):
        result = duckdb_read_parquet_sql(s3=S3_MINIO, key="k")
        assert "SET s3_endpoint='localhost:9000'" in result.config_sql
        assert "SET s3_access_key_id='minio'" in result.config_sql
        assert "SET s3_region='us-east-1'" in result.config_sql
        assert "SET s3_url_style='path'" in result.config_sql
        assert "SET s3_use_ssl=false" in result.config_sql
        # The secret access key must never appear in the redactable config_sql.
        assert "s3_secret_access_key" not in result.config_sql
        assert "minio123" not in result.config_sql

    def test_secret_excluded_from_redactable_sql(self):
        result = duckdb_read_parquet_sql(s3=S3_MINIO, key="k")
        # Redactable fields (safe to log) must not leak the secret.
        assert "minio123" not in result.config_sql
        assert "minio123" not in result.sql
        assert "s3_secret_access_key" not in result.sql
        # The credential lives only in the clearly-marked fields.
        assert result.credential_sql == "SET s3_secret_access_key='minio123';"
        assert "SET s3_secret_access_key='minio123'" in result.runnable_sql

    def test_runnable_sql_concatenates_all_parts(self):
        result = duckdb_read_parquet_sql(s3=S3_MINIO, key="k")
        assert result.setup_sql in result.runnable_sql
        assert result.config_sql in result.runnable_sql
        assert result.credential_sql in result.runnable_sql
        assert result.read_sql in result.runnable_sql

    def test_read_sql(self):
        result = duckdb_read_parquet_sql(s3=S3_MINIO, key="datasets/alice/q1.parquet")
        assert result.read_sql == "SELECT * FROM read_parquet('s3://my-bucket/datasets/alice/q1.parquet');"

    def test_sql_concatenates_all_parts(self):
        result = duckdb_read_parquet_sql(s3=S3_MINIO, key="k")
        assert result.setup_sql in result.sql
        assert result.config_sql in result.sql
        assert result.read_sql in result.sql

    def test_aws_https_ssl_and_vhost(self):
        result = duckdb_read_parquet_sql(s3=S3_AWS, key="k", force_path_style=False)
        assert "SET s3_url_style='vhost'" in result.config_sql
        assert "SET s3_use_ssl=true" in result.config_sql
        assert "SET s3_region='eu-west-1'" in result.config_sql

    def test_glob_appends_wildcard(self):
        result = duckdb_read_parquet_sql(s3=S3_MINIO, key="datasets/alice", glob=True)
        assert result.uri == "s3://my-bucket/datasets/alice/*.parquet"
        assert "*.parquet" in result.read_sql

    def test_glob_normalizes_trailing_slash(self):
        result = duckdb_read_parquet_sql(s3=S3_MINIO, key="datasets/alice/", glob=True)
        assert result.uri == "s3://my-bucket/datasets/alice/*.parquet"

    def test_single_quotes_in_credentials_and_key_are_escaped(self):
        """SQL injection guard: single quotes in credentials/key must be doubled."""
        from dataclasses import replace
        s3_with_quote = replace(
            S3_MINIO,
            secret_access_key="sec'ret",
            access_key_id="aki'd",
        )
        result = duckdb_read_parquet_sql(s3=s3_with_quote, key="datasets/alice'x/q1.parquet")
        # Check the full runnable script — it is the only field carrying the secret.
        assert "sec''ret" in result.runnable_sql
        assert "aki''d" in result.runnable_sql
        assert "alice''x" in result.runnable_sql
        # raw unescaped single quotes must not appear inside any SQL string value
        without_setup = result.runnable_sql.replace("INSTALL httpfs;\nLOAD httpfs;", "")
        import re
        lone_quotes = re.findall(r"(?<!')'(?!')", without_setup)
        # Only the structural quotes wrapping each SET value and read_parquet remain
        assert len(lone_quotes) <= 14


# ---------------------------------------------------------------------------
# Integration: push/pull Parquet via MemoryObjectStore
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_parquet_push_pull_roundtrip():
    """Push raw Parquet bytes, pull them back identically."""
    app, _ = _build_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        push_resp = await client.post(
            "/push/datasets/user-1/q1.parquet",
            content=PARQUET_BYTES,
            headers={"content-type": PARQUET_MIME_TYPE},
        )
        assert push_resp.status_code == 200
        assert push_resp.json()["hash"] == hashlib.sha256(PARQUET_BYTES).hexdigest()

        pull_resp = await client.get("/pull/datasets/user-1/q1.parquet")
        assert pull_resp.status_code == 200
        assert pull_resp.content == PARQUET_BYTES
        assert PARQUET_MIME_TYPE in pull_resp.headers["content-type"]


@pytest.mark.asyncio
async def test_parquet_rejects_json_content_type():
    """JSON Content-Type is not in PARQUET_MIME_TYPES → 415."""
    app, _ = _build_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/datasets/user-1/q1.parquet",
            content=b'{"data":{}}',
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 415


@pytest.mark.asyncio
async def test_parquet_accepts_octet_stream():
    """application/octet-stream is in PARQUET_MIME_TYPES → 200."""
    app, _ = _build_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/datasets/user-1/q1.parquet",
            content=PARQUET_BYTES,
            headers={"content-type": "application/octet-stream"},
        )
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_parquet_pull_empty_404():
    """Pull from empty Parquet collection returns 404."""
    app, _ = _build_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/datasets/user-1/missing.parquet")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_parquet_last_write_wins():
    """Second push overwrites the first (no conflict detection)."""
    app, _ = _build_app()
    bytes_v1 = b"PAR1-v1"
    bytes_v2 = b"PAR1-v2"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/push/datasets/user-1/file.parquet",
            content=bytes_v1,
            headers={"content-type": PARQUET_MIME_TYPE},
        )
        await client.post(
            "/push/datasets/user-1/file.parquet",
            content=bytes_v2,
            headers={"content-type": PARQUET_MIME_TYPE},
        )
        pull_resp = await client.get("/pull/datasets/user-1/file.parquet")
        assert pull_resp.content == bytes_v2


# ---------------------------------------------------------------------------
# create_sealed_parquet_collection — config factory
# ---------------------------------------------------------------------------


class TestCreateSealedParquetCollection:
    def test_defaults(self):
        col = create_sealed_parquet_collection(
            name="enc-datasets", storage_path="enc/{spaceId}/{objectId}"
        )
        assert col.name == "enc-datasets"
        # E2EE preset defaults to authenticated read (not public).
        assert col.read_roles == ["cap:read:enc-datasets"]
        assert col.write_roles == ["cap:write:enc-datasets"]
        assert col.encryption == "none"
        assert col.max_body_bytes == 256 * 1024 * 1024
        assert col.allowed_mime_types == ["application/octet-stream"]
        assert col.rate_limit is None

    def test_allowed_mime_types_is_octet_stream_not_parquet(self):
        col = create_sealed_parquet_collection(name="x", storage_path="x/{id}")
        assert col.allowed_mime_types == ["application/octet-stream"]
        assert "application/vnd.apache.parquet" not in col.allowed_mime_types

    def test_forces_encryption_none(self):
        col = create_sealed_parquet_collection(name="x", storage_path="x/{id}")
        assert col.encryption == "none"

    def test_read_public(self):
        col = create_sealed_parquet_collection(
            name="x", storage_path="x/{id}", read="public", write="authenticated"
        )
        assert col.read_roles == ["public"]
        assert col.push_only is None

    def test_read_authenticated(self):
        col = create_sealed_parquet_collection(
            name="x", storage_path="x/{id}", read="authenticated", write="public"
        )
        assert col.read_roles == ["cap:read:x"]

    def test_read_none_sets_push_only(self):
        col = create_sealed_parquet_collection(
            name="x", storage_path="x/{id}", read="none", write="public"
        )
        assert col.push_only is True
        assert col.pull_only is None

    def test_write_none_sets_pull_only(self):
        col = create_sealed_parquet_collection(
            name="x", storage_path="x/{id}", read="public", write="none"
        )
        assert col.pull_only is True
        assert col.push_only is None

    def test_custom_role_list(self):
        col = create_sealed_parquet_collection(
            name="x",
            storage_path="x/{id}",
            read=["space:member"],
            write=["space:member"],
        )
        assert col.read_roles == ["space:member"]
        assert col.write_roles == ["space:member"]

    def test_raises_when_both_none(self):
        with pytest.raises(ValueError, match='both read and write are "none"'):
            create_sealed_parquet_collection(
                name="x", storage_path="x/{id}", read="none", write="none"
            )

    def test_auto_listable_when_last_segment_is_param(self):
        col = create_sealed_parquet_collection(
            name="x", storage_path="spaces/{spaceId}/enc/{objectId}"
        )
        assert col.listable is True

    def test_no_listable_when_last_segment_is_literal(self):
        col = create_sealed_parquet_collection(
            name="x", storage_path="spaces/{spaceId}/enc/fixed"
        )
        assert not col.listable

    def test_max_body_bytes_override(self):
        col = create_sealed_parquet_collection(
            name="x", storage_path="x/{id}", max_body_bytes=67_108_864
        )
        assert col.max_body_bytes == 67_108_864

    def test_cache_duration_forwarded(self):
        col = create_sealed_parquet_collection(
            name="x", storage_path="x/{id}", cache_duration_ms=60_000
        )
        assert col.cache_duration_ms == 60_000

    def test_passes_validate_config(self):
        col = create_sealed_parquet_collection(
            name="private-datasets",
            storage_path="spaces/{spaceId}/objects/parquet-enc/{objectId}",
            read=["space:member"],
            write=["space:member"],
            max_body_bytes=67_108_864,
        )
        errors = validate_config(SyncConfig(version=1, collections=[col]))
        assert errors == []


# ---------------------------------------------------------------------------
# Integration: sealed collection accepts octet-stream, rejects parquet MIME
# ---------------------------------------------------------------------------


@pytest.mark.anyio
class TestSealedParquetCollectionIntegration:
    async def test_pushes_octet_stream_and_pulls_back(self):
        col = create_sealed_parquet_collection(
            name="enc-datasets",
            storage_path="enc/{spaceId}/{objectId}",
            read=["space:member"],
            write=["space:member"],
        )
        store = MemoryObjectStore()
        config = SyncConfig(version=1, collections=[col])

        async def role_resolver(request) -> AuthResult:
            return AuthResult(identity="user-1", roles=["space:member"])

        router = create_sync_router(
            SyncRouterOptions(store=store, config=config, role_resolver=role_resolver)
        )
        app = FastAPI()
        app.include_router(router)

        # Simulated AES-GCM sealed bytes (opaque binary)
        sealed = bytes([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x01, 0x02])

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            push_resp = await client.post(
                "/push/enc/space-1/obj-1",
                content=sealed,
                headers={"content-type": "application/octet-stream"},
            )
            assert push_resp.status_code == 200
            pull_resp = await client.get("/pull/enc/space-1/obj-1")
            assert pull_resp.status_code == 200
            assert pull_resp.content == sealed

    async def test_rejects_parquet_mime_type(self):
        col = create_sealed_parquet_collection(
            name="enc-datasets",
            storage_path="enc/{spaceId}/{objectId}",
        )
        store = MemoryObjectStore()
        config = SyncConfig(version=1, collections=[col])

        async def role_resolver(request) -> AuthResult:
            return AuthResult(
                identity="user-1", roles=["public", "cap:write:enc-datasets"]
            )

        router = create_sync_router(
            SyncRouterOptions(store=store, config=config, role_resolver=role_resolver)
        )
        app = FastAPI()
        app.include_router(router)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/push/enc/space-1/obj-1",
                content=PARQUET_BYTES,
                headers={"content-type": PARQUET_MIME_TYPE},
            )
            assert resp.status_code == 415
