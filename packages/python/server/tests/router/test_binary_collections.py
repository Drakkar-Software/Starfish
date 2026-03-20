"""Tests for binary (non-JSON) collection support via allowedMimeTypes."""

import hashlib

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import (
    SyncConfig,
    CollectionConfig,
    RateLimitConfig,
    RemoteConfig,
)
from starfish_server.config.validate import validate_config
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from starfish_server.router.mime import matches_allowed_mime, is_json_collection
from tests.helpers import MemoryObjectStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
JPEG_BYTES = b"\xff\xd8\xff\xe0" + b"\x00" * 100


def _build_app(
    collections: list[CollectionConfig],
    global_rate_limit: RateLimitConfig | None = None,
    identity: str = "user-1",
    roles: list[str] | None = None,
) -> tuple[FastAPI, MemoryObjectStore]:
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=collections,
        rateLimit=global_rate_limit,
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=roles or [])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


def _binary_col(
    name: str = "logos",
    allowed_mime_types: list[str] | None = None,
    encryption: str = "none",
    **kwargs,
) -> CollectionConfig:
    return CollectionConfig(
        name=name,
        storagePath=f"users/{{identity}}/{name}",
        readRoles=["self"],
        writeRoles=["self"],
        encryption=encryption,
        maxBodyBytes=65536,
        allowedMimeTypes=allowed_mime_types or ["image/*"],
        **kwargs,
    )


# ---------------------------------------------------------------------------
# MIME matching utility
# ---------------------------------------------------------------------------

class TestMatchesAllowedMime:
    def test_wildcard_matches(self):
        assert matches_allowed_mime("image/png", ["image/*"]) is True
        assert matches_allowed_mime("image/jpeg", ["image/*"]) is True

    def test_wildcard_rejects_different_type(self):
        assert matches_allowed_mime("application/pdf", ["image/*"]) is False

    def test_exact_match(self):
        assert matches_allowed_mime("application/pdf", ["application/pdf"]) is True

    def test_exact_mismatch(self):
        assert matches_allowed_mime("application/pdf", ["image/png"]) is False

    def test_star_star_matches_everything(self):
        assert matches_allowed_mime("image/png", ["*/*"]) is True
        assert matches_allowed_mime("application/json", ["*/*"]) is True

    def test_strips_parameters(self):
        assert matches_allowed_mime("image/png; charset=utf-8", ["image/*"]) is True

    def test_case_insensitive(self):
        assert matches_allowed_mime("Image/PNG", ["image/*"]) is True
        assert matches_allowed_mime("image/png", ["Image/*"]) is True

    def test_empty_content_type(self):
        assert matches_allowed_mime("", ["image/*"]) is False

    def test_multiple_patterns(self):
        patterns = ["image/png", "image/jpeg", "application/pdf"]
        assert matches_allowed_mime("image/jpeg", patterns) is True
        assert matches_allowed_mime("application/pdf", patterns) is True
        assert matches_allowed_mime("text/html", patterns) is False


class TestIsJsonCollection:
    def test_default_is_json(self):
        assert is_json_collection(["application/json"]) is True

    def test_binary_is_not_json(self):
        assert is_json_collection(["image/png"]) is False
        assert is_json_collection(["image/*"]) is False

    def test_mixed_is_json(self):
        assert is_json_collection(["application/json", "image/*"]) is True

    def test_case_insensitive(self):
        assert is_json_collection(["Application/JSON"]) is True


# ---------------------------------------------------------------------------
# Config: allowedMimeTypes field
# ---------------------------------------------------------------------------

class TestAllowedMimeTypesConfig:
    def test_default_is_json(self):
        col = CollectionConfig(
            name="x", storagePath="x", readRoles=["self"],
            writeRoles=["self"], encryption="none", maxBodyBytes=1024,
        )
        assert col.allowed_mime_types == ["application/json"]

    def test_set_via_alias(self):
        col = _binary_col(allowed_mime_types=["image/png", "image/jpeg"])
        assert col.allowed_mime_types == ["image/png", "image/jpeg"]

    def test_set_via_python_name(self):
        col = CollectionConfig(
            name="x", storagePath="x", readRoles=["self"],
            writeRoles=["self"], encryption="none", maxBodyBytes=1024,
            allowed_mime_types=["application/pdf"],
        )
        assert col.allowed_mime_types == ["application/pdf"]


# ---------------------------------------------------------------------------
# Config validation for binary collections
# ---------------------------------------------------------------------------

def _config(*cols: CollectionConfig) -> SyncConfig:
    return SyncConfig(version=1, collections=list(cols))


class TestBinaryCollectionValidation:
    def test_binary_with_identity_encryption_rejected(self):
        col = _binary_col(encryption="identity")
        errors = validate_config(_config(col))
        assert any("binary" in e and "encryption" in e for e in errors)

    def test_binary_with_server_encryption_rejected(self):
        col = _binary_col(encryption="server")
        errors = validate_config(_config(col))
        assert any("binary" in e and "encryption" in e for e in errors)

    def test_binary_with_none_encryption_passes(self):
        col = _binary_col(encryption="none")
        errors = validate_config(_config(col))
        assert not any("binary" in e for e in errors)

    def test_binary_with_delegated_encryption_passes(self):
        col = _binary_col(encryption="delegated")
        errors = validate_config(_config(col))
        assert not any("binary" in e and "encryption" in e for e in errors)

    def test_binary_with_object_schema_rejected(self):
        col = _binary_col(objectSchema={"type": "object"})
        errors = validate_config(_config(col))
        assert any("binary" in e and "objectSchema" in e for e in errors)

    def test_binary_with_bundle_rejected(self):
        col = _binary_col(bundle="my-bundle")
        errors = validate_config(_config(col))
        assert any("binary" in e and "bundle" in e for e in errors)

    def test_binary_with_remote_rejected(self):
        col = CollectionConfig(
            name="logos",
            storagePath="static/logos",
            readRoles=["public"],
            writeRoles=[],
            encryption="none",
            maxBodyBytes=65536,
            allowedMimeTypes=["image/*"],
            pullOnly=True,
            remote=RemoteConfig(
                url="https://primary.example.com/v1",
                pullPath="/pull/static/logos",
            ),
        )
        errors = validate_config(_config(col))
        assert any("binary" in e and "remote" in e for e in errors)

    def test_empty_allowed_mime_types_rejected(self):
        col = CollectionConfig(
            name="empty",
            storagePath="x",
            readRoles=["self"],
            writeRoles=["self"],
            encryption="none",
            maxBodyBytes=1024,
            allowedMimeTypes=[],
        )
        errors = validate_config(_config(col))
        assert any("allowedMimeTypes" in e and "at least one" in e for e in errors)

    def test_json_collection_with_encryption_passes(self):
        """Default JSON collections are unaffected by binary validation."""
        col = CollectionConfig(
            name="settings",
            storagePath="users/{identity}/settings",
            readRoles=["self"],
            writeRoles=["self"],
            encryption="identity",
            maxBodyBytes=65536,
        )
        errors = validate_config(_config(col))
        assert not any("binary" in e for e in errors)


# ---------------------------------------------------------------------------
# Binary push/pull roundtrip
# ---------------------------------------------------------------------------

PUSH_PATH = "/push/users/user-1/logos"
PULL_PATH = "/pull/users/user-1/logos"


@pytest.mark.asyncio
async def test_binary_push_pull_roundtrip():
    """Push raw PNG bytes, pull them back identically."""
    app, _ = _build_app([_binary_col()])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        push_resp = await client.post(
            PUSH_PATH, content=PNG_BYTES,
            headers={"content-type": "image/png"},
        )
        assert push_resp.status_code == 200
        push_body = push_resp.json()
        assert push_body["hash"] == hashlib.sha256(PNG_BYTES).hexdigest()

        pull_resp = await client.get(PULL_PATH)
        assert pull_resp.status_code == 200
        assert pull_resp.content == PNG_BYTES
        assert "image/png" in pull_resp.headers["content-type"]


@pytest.mark.asyncio
async def test_binary_pull_returns_etag():
    """Pull response includes an ETag header."""
    app, _ = _build_app([_binary_col()])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(PUSH_PATH, content=PNG_BYTES, headers={"content-type": "image/png"})
        pull_resp = await client.get(PULL_PATH)
        expected_etag = f'"{hashlib.sha256(PNG_BYTES).hexdigest()}"'
        assert pull_resp.headers["etag"] == expected_etag


@pytest.mark.asyncio
async def test_binary_push_overwrite():
    """Second push overwrites the first (no conflict detection)."""
    app, _ = _build_app([_binary_col()])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(PUSH_PATH, content=PNG_BYTES, headers={"content-type": "image/png"})
        await client.post(PUSH_PATH, content=JPEG_BYTES, headers={"content-type": "image/jpeg"})

        pull_resp = await client.get(PULL_PATH)
        assert pull_resp.content == JPEG_BYTES
        assert "image/jpeg" in pull_resp.headers["content-type"]


# ---------------------------------------------------------------------------
# MIME type rejection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_binary_push_wrong_mime_rejected():
    """Push with a Content-Type not matching allowedMimeTypes returns 415."""
    app, _ = _build_app([_binary_col(allowed_mime_types=["image/*"])])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            PUSH_PATH, content=b"not an image",
            headers={"content-type": "application/pdf"},
        )
        assert resp.status_code == 415
        assert "not allowed" in resp.json()["error"]


@pytest.mark.asyncio
async def test_binary_push_exact_mime_accepted():
    """Push with exact MIME match succeeds."""
    col = _binary_col(allowed_mime_types=["application/pdf"])
    app, _ = _build_app([col])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            PUSH_PATH, content=b"%PDF-1.4",
            headers={"content-type": "application/pdf"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Binary pull: 404 when no content
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_binary_pull_empty_returns_404():
    """Pull from a binary collection with no stored data returns 404."""
    app, _ = _build_app([_binary_col()])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(PULL_PATH)
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Body limit on binary push
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_binary_push_body_limit():
    """Binary push respects maxBodyBytes."""
    col = _binary_col()  # maxBodyBytes=65536
    app, _ = _build_app([col])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            PUSH_PATH, content=PNG_BYTES,
            headers={"content-type": "image/png", "content-length": "999999"},
        )
        assert resp.status_code == 413


# ---------------------------------------------------------------------------
# Rate limiting on binary push
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_binary_push_rate_limited():
    """Rate limiting works on binary push."""
    global_rl = RateLimitConfig(windowMs=60_000, maxRequests=1)
    col = _binary_col(rateLimit=True)
    app, _ = _build_app([col], global_rate_limit=global_rl)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(PUSH_PATH, content=PNG_BYTES, headers={"content-type": "image/png"})
        assert resp.status_code == 200

        resp = await client.post(PUSH_PATH, content=PNG_BYTES, headers={"content-type": "image/png"})
        assert resp.status_code == 429


# ---------------------------------------------------------------------------
# Cache-Control on binary pull
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_binary_pull_cache_control():
    """cacheDurationMs adds Cache-Control header to binary pull."""
    col = _binary_col(cacheDurationMs=30_000)
    app, _ = _build_app([col])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(PUSH_PATH, content=PNG_BYTES, headers={"content-type": "image/png"})
        resp = await client.get(PULL_PATH)
        assert resp.headers["cache-control"] == "private, max-age=30"


@pytest.mark.asyncio
async def test_binary_pull_public_cache_control():
    """Public binary collection gets max-age without private directive."""
    col = CollectionConfig(
        name="logos",
        storagePath="logos",
        readRoles=["public"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
        allowedMimeTypes=["image/*"],
        cacheDurationMs=60_000,
    )
    app, _ = _build_app([col], roles=["admin"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/push/logos", content=PNG_BYTES, headers={"content-type": "image/png"})
        resp = await client.get("/pull/logos")
        assert resp.headers["cache-control"] == "max-age=60"


# ---------------------------------------------------------------------------
# JSON collections unaffected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_json_collection_still_works():
    """Default allowedMimeTypes (application/json) preserves existing behavior."""
    col = CollectionConfig(
        name="settings",
        storagePath="users/{identity}/settings",
        readRoles=["self"],
        writeRoles=["self"],
        encryption="none",
        maxBodyBytes=65536,
        # No allowedMimeTypes → defaults to ["application/json"]
    )
    app, _ = _build_app([col])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        push_resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"theme": "dark"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        assert push_resp.status_code == 200

        pull_resp = await client.get("/pull/users/user-1/settings")
        assert pull_resp.status_code == 200
        assert pull_resp.json()["data"] == {"theme": "dark"}


@pytest.mark.asyncio
async def test_json_collection_rejects_binary():
    """JSON collection still rejects non-JSON content types."""
    col = CollectionConfig(
        name="settings",
        storagePath="users/{identity}/settings",
        readRoles=["self"],
        writeRoles=["self"],
        encryption="none",
        maxBodyBytes=65536,
    )
    app, _ = _build_app([col])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/settings",
            content=PNG_BYTES,
            headers={"content-type": "image/png"},
        )
        assert resp.status_code == 415
