"""Tests for namespace routing — ported from namespace.test.ts."""

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig, NamespaceConfig
from starfish_server.router.route_builder import create_sync_router, SyncRouterOptions, AuthResult
from tests.helpers import MemoryObjectStore


_SETTINGS_COL = CollectionConfig(
    name="settings",
    storagePath="users/{identity}/settings",
    readRoles=["self"],
    writeRoles=["self"],
    encryption="none",
    maxBodyBytes=1_000_000,
)

_PUBLIC_COL = CollectionConfig(
    name="config",
    storagePath="app/config",
    readRoles=["public"],
    writeRoles=["admin"],
    encryption="none",
    maxBodyBytes=1_000_000,
)


def _make_app(
    config: SyncConfig,
    identity: str = "user-1",
    roles: list[str] | None = None,
) -> FastAPI:
    store = MemoryObjectStore()

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=roles or [])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app


# ---------------------------------------------------------------------------
# Basic namespace routing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_namespaced_pull_at_ns_prefix():
    app = _make_app(SyncConfig(
        version=1, collections=[],
        namespaces={"tenantA": NamespaceConfig(collections=[_SETTINGS_COL])},
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/tenantA/pull/users/user-1/settings")
    assert resp.status_code == 200
    assert resp.json()["data"] == {}


@pytest.mark.asyncio
async def test_namespaced_push_at_ns_prefix():
    app = _make_app(SyncConfig(
        version=1, collections=[],
        namespaces={"tenantA": NamespaceConfig(collections=[_SETTINGS_COL])},
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/tenantA/push/users/user-1/settings",
            json={"data": {"theme": "dark"}, "baseHash": None},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert "hash" in body
    assert "timestamp" in body


@pytest.mark.asyncio
async def test_root_collections_unaffected_by_namespaces():
    app = _make_app(SyncConfig(
        version=1,
        collections=[_SETTINGS_COL],
        namespaces={"tenantA": NamespaceConfig(collections=[
            CollectionConfig(**{**_SETTINGS_COL.model_dump(), "name": "prefs"}),
        ])},
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/users/user-1/settings")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_namespace_and_root_routes_are_independent():
    ns_col = CollectionConfig(
        **{**_SETTINGS_COL.model_dump(), "storagePath": "tenantA/users/{identity}/settings"},
    )
    app = _make_app(SyncConfig(
        version=1,
        collections=[_SETTINGS_COL],
        namespaces={"tenantA": NamespaceConfig(collections=[ns_col])},
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Push to namespace
        ns_push = await client.post(
            "/tenantA/push/tenantA/users/user-1/settings",
            json={"data": {"source": "tenantA"}, "baseHash": None},
        )
        assert ns_push.status_code == 200

        # Push to root
        root_push = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"source": "root"}, "baseHash": None},
        )
        assert root_push.status_code == 200

        # Each reads its own data
        ns_body = (await client.get("/tenantA/pull/tenantA/users/user-1/settings")).json()
        root_body = (await client.get("/pull/users/user-1/settings")).json()

    assert ns_body["data"]["source"] == "tenantA"
    assert root_body["data"]["source"] == "root"


@pytest.mark.asyncio
async def test_multiple_namespaces_with_distinct_storage_paths_are_isolated():
    col_a = CollectionConfig(
        **{**_SETTINGS_COL.model_dump(), "storagePath": "tenantA/users/{identity}/settings"},
    )
    col_b = CollectionConfig(
        **{**_SETTINGS_COL.model_dump(), "storagePath": "tenantB/users/{identity}/settings"},
    )
    app = _make_app(SyncConfig(
        version=1, collections=[],
        namespaces={
            "tenantA": NamespaceConfig(collections=[col_a]),
            "tenantB": NamespaceConfig(collections=[col_b]),
        },
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/tenantA/push/tenantA/users/user-1/settings",
            json={"data": {"tenant": "A"}, "baseHash": None},
        )
        b_resp = await client.get("/tenantB/pull/tenantB/users/user-1/settings")

    assert b_resp.json()["data"] == {}


@pytest.mark.asyncio
async def test_unknown_namespace_returns_404():
    app = _make_app(SyncConfig(
        version=1, collections=[],
        namespaces={"tenantA": NamespaceConfig(collections=[_SETTINGS_COL])},
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/tenantB/pull/users/user-1/settings")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_auth_enforced_on_namespaced_pull():
    app = _make_app(
        SyncConfig(
            version=1, collections=[],
            namespaces={"tenantA": NamespaceConfig(collections=[_SETTINGS_COL])},
        ),
        identity="user-2",
        roles=[],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/tenantA/pull/users/user-1/settings")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_health_at_root_not_namespaced():
    app = _make_app(SyncConfig(
        version=1, collections=[],
        namespaces={"tenantA": NamespaceConfig(collections=[_SETTINGS_COL])},
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


# ---------------------------------------------------------------------------
# Namespace push auth
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_auth_enforced_on_namespaced_push():
    app = _make_app(
        SyncConfig(
            version=1, collections=[],
            namespaces={"tenantA": NamespaceConfig(collections=[_SETTINGS_COL])},
        ),
        identity="user-2",
        roles=[],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/tenantA/push/users/user-1/settings",
            json={"data": {"x": 1}, "baseHash": None},
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_namespaced_push_data_readable_via_namespaced_pull():
    app = _make_app(SyncConfig(
        version=1, collections=[],
        namespaces={"tenantA": NamespaceConfig(collections=[_SETTINGS_COL])},
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/tenantA/push/users/user-1/settings",
            json={"data": {"color": "blue"}, "baseHash": None},
        )
        resp = await client.get("/tenantA/pull/users/user-1/settings")

    assert resp.json()["data"]["color"] == "blue"


# ---------------------------------------------------------------------------
# Namespace shared storagePath behavior (documented)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_two_namespaces_with_same_storage_path_share_data():
    """Namespaces are URL prefixes only; storage isolation requires distinct storagePaths."""
    app = _make_app(SyncConfig(
        version=1, collections=[],
        namespaces={
            "tenantA": NamespaceConfig(collections=[_SETTINGS_COL]),
            "tenantB": NamespaceConfig(collections=[_SETTINGS_COL]),
        },
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/tenantA/push/users/user-1/settings",
            json={"data": {"source": "A"}, "baseHash": None},
        )
        resp = await client.get("/tenantB/pull/users/user-1/settings")

    assert resp.json()["data"]["source"] == "A"


# ---------------------------------------------------------------------------
# Namespace batch pull
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ns_batch_pull_returns_collections_in_namespace():
    app = _make_app(SyncConfig(
        version=1, collections=[],
        namespaces={"tenantA": NamespaceConfig(collections=[_PUBLIC_COL])},
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/tenantA/batch/pull?collections=config")
    assert resp.status_code == 200
    body = resp.json()
    assert "config" in body["collections"]
    assert "error" not in body["collections"]["config"]


@pytest.mark.asyncio
async def test_ns_batch_pull_does_not_find_root_collections():
    app = _make_app(SyncConfig(
        version=1,
        collections=[_PUBLIC_COL],
        namespaces={"tenantA": NamespaceConfig(collections=[_SETTINGS_COL])},
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/tenantA/batch/pull?collections=config")
    assert resp.status_code == 200
    assert resp.json()["collections"]["config"]["error"] == "Collection not found"


@pytest.mark.asyncio
async def test_root_batch_pull_does_not_find_namespaced_collections():
    app = _make_app(SyncConfig(
        version=1, collections=[],
        namespaces={"tenantA": NamespaceConfig(collections=[_PUBLIC_COL])},
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull?collections=config")
    assert resp.status_code == 200
    assert resp.json()["collections"]["config"]["error"] == "Collection not found"


@pytest.mark.asyncio
async def test_ns_batch_pull_returns_400_for_missing_collections_param():
    app = _make_app(SyncConfig(
        version=1, collections=[],
        namespaces={"tenantA": NamespaceConfig(collections=[_PUBLIC_COL])},
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/tenantA/batch/pull")
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Root batch pull
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_root_batch_pull_returns_root_collections():
    app = _make_app(SyncConfig(
        version=1, collections=[_PUBLIC_COL], namespaces=None,
    ))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull?collections=config")
    assert resp.status_code == 200
    body = resp.json()
    assert "config" in body["collections"]
    assert "error" not in body["collections"]["config"]


@pytest.mark.asyncio
async def test_root_batch_pull_returns_error_for_unknown_collection():
    app = _make_app(SyncConfig(version=1, collections=[_PUBLIC_COL]))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull?collections=nonexistent")
    assert resp.status_code == 200
    assert resp.json()["collections"]["nonexistent"]["error"] == "Collection not found"


@pytest.mark.asyncio
async def test_root_batch_pull_returns_400_for_missing_param():
    app = _make_app(SyncConfig(version=1, collections=[_PUBLIC_COL]))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull")
    assert resp.status_code == 400
