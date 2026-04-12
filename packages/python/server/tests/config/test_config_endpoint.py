"""Tests for GET /config endpoint."""

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig, ConfigEndpointOptions, NamespaceConfig
from starfish_server.router.route_builder import create_sync_router, SyncRouterOptions, AuthResult
from tests.helpers import MemoryObjectStore


def _make_col(**overrides) -> CollectionConfig:
    defaults = dict(
        name="posts",
        storagePath="posts/{postId}",
        readRoles=["public"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
    )
    defaults.update(overrides)
    return CollectionConfig(**defaults)


def _build_app(
    cols: list[CollectionConfig],
    config_endpoint: ConfigEndpointOptions | None = None,
    role_resolver=None,
    namespaces: dict | None = None,
):
    store = MemoryObjectStore()

    async def default_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["admin"])

    ns_config = {k: NamespaceConfig(collections=v) for k, v in (namespaces or {}).items()}

    config = SyncConfig(version=1, collections=cols, namespaces=ns_config or None)
    router = create_sync_router(
        SyncRouterOptions(
            store=store,
            config=config,
            role_resolver=role_resolver or default_resolver,
            config_endpoint=config_endpoint,
        )
    )
    app = FastAPI()
    app.include_router(router)
    return app


# ---------------------------------------------------------------------------
# Disabled by default
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_endpoint_disabled_by_default():
    app = _build_app([_make_col()])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/config")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# auth: public
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_public_returns_all_collections():
    cols = [
        _make_col(name="posts", storagePath="posts/{id}"),
        _make_col(name="comments", storagePath="comments/{id}", writeRoles=["user"]),
    ]
    app = _build_app(cols, config_endpoint=ConfigEndpointOptions(auth="public"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/config")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["collections"]) == 2
    names = {c["name"] for c in body["collections"]}
    assert names == {"posts", "comments"}


@pytest.mark.asyncio
async def test_public_includes_public_key():
    col = _make_col(publicKey="base64encodedkey==")
    app = _build_app([col], config_endpoint=ConfigEndpointOptions(auth="public"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/config")
    body = resp.json()
    assert body["collections"][0]["publicKey"] == "base64encodedkey=="


@pytest.mark.asyncio
async def test_public_omits_public_key_when_not_set():
    app = _build_app([_make_col()], config_endpoint=ConfigEndpointOptions(auth="public"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/config")
    body = resp.json()
    assert body["collections"][0].get("publicKey") is None


@pytest.mark.asyncio
async def test_public_capability_fields():
    col = _make_col(pullOnly=True, ttlMs=3_600_000)
    app = _build_app([col], config_endpoint=ConfigEndpointOptions(auth="public"))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/config")
    body = resp.json()
    c = body["collections"][0]
    assert c["maxBodyBytes"] == 65536
    assert c["encryption"] == "none"
    assert c["allowedMimeTypes"] == ["application/json"]
    assert c["pullOnly"] is True
    assert c["ttlMs"] == 3_600_000


@pytest.mark.asyncio
async def test_public_includes_namespace_collections():
    root_col = _make_col(name="posts", storagePath="posts/{id}")
    ns_col = _make_col(name="settings", storagePath="settings/{id}")
    app = _build_app(
        [root_col],
        config_endpoint=ConfigEndpointOptions(auth="public"),
        namespaces={"tenantA": [ns_col]},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/config")
    body = resp.json()
    assert len(body["collections"]) == 1
    assert body["namespaces"]["tenantA"]["collections"][0]["name"] == "settings"


# ---------------------------------------------------------------------------
# auth: role-filtered
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_role_filtered_shows_accessible_collections():
    cols = [
        _make_col(name="posts", storagePath="posts/{id}", readRoles=["public"], writeRoles=["admin"]),
        _make_col(name="secrets", storagePath="secrets/{id}", readRoles=["admin"], writeRoles=["admin"]),
    ]

    async def anon_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="anon", roles=["public"])

    app = _build_app(
        cols,
        config_endpoint=ConfigEndpointOptions(auth="role-filtered"),
        role_resolver=anon_resolver,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/config")
    body = resp.json()
    assert len(body["collections"]) == 1
    assert body["collections"][0]["name"] == "posts"


@pytest.mark.asyncio
async def test_role_filtered_shows_nothing_for_no_matching_roles():
    async def resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user", roles=["user"])

    app = _build_app(
        [_make_col(readRoles=["admin"], writeRoles=["admin"])],
        config_endpoint=ConfigEndpointOptions(auth="role-filtered"),
        role_resolver=resolver,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/config")
    body = resp.json()
    assert body["collections"] == []


@pytest.mark.asyncio
async def test_role_filtered_matches_write_roles():
    async def resolver(request: Request) -> AuthResult:
        return AuthResult(identity="w", roles=["writer"])

    app = _build_app(
        [_make_col(name="pushonly", storagePath="p/{id}", readRoles=[], writeRoles=["writer"], pushOnly=True)],
        config_endpoint=ConfigEndpointOptions(auth="role-filtered"),
        role_resolver=resolver,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/config")
    body = resp.json()
    assert len(body["collections"]) == 1


@pytest.mark.asyncio
async def test_role_filtered_filters_namespace_collections():
    public_col = _make_col(name="pub", storagePath="pub/{id}", readRoles=["public"], writeRoles=["admin"])
    secret_col = _make_col(name="secret", storagePath="sec/{id}", readRoles=["admin"], writeRoles=["admin"])

    async def anon_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="anon", roles=["public"])

    app = _build_app(
        [],
        config_endpoint=ConfigEndpointOptions(auth="role-filtered"),
        role_resolver=anon_resolver,
        namespaces={"ns1": [public_col, secret_col]},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/config")
    body = resp.json()
    assert body["namespaces"]["ns1"]["collections"] == [{"name": "pub", "maxBodyBytes": 65536, "encryption": "none", "allowedMimeTypes": ["application/json"]}]


@pytest.mark.asyncio
async def test_role_filtered_returns_empty_on_resolver_error():
    async def failing_resolver(request: Request) -> AuthResult:
        raise RuntimeError("auth failure")

    app = _build_app(
        [_make_col()],
        config_endpoint=ConfigEndpointOptions(auth="role-filtered"),
        role_resolver=failing_resolver,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/config")
    assert resp.status_code == 200
    body = resp.json()
    assert body["collections"] == []
