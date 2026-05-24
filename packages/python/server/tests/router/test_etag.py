"""Tests for ETag conditional request support."""

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig, FieldPermission
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from tests.helpers import MemoryObjectStore


def _build_app() -> tuple[FastAPI, MemoryObjectStore]:
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="settings",
                storagePath="users/{identity}/settings",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=[])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


@pytest.mark.asyncio
async def test_pull_includes_etag_header():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Push data
        await client.post(
            "/push/users/user-1/settings",
            json={"data": {"theme": "dark"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        # Pull and check ETag
        resp = await client.get("/pull/users/user-1/settings")
    assert resp.status_code == 200
    etag = resp.headers.get("etag")
    assert etag is not None
    assert etag.startswith('"') and etag.endswith('"')


@pytest.mark.asyncio
async def test_304_when_etag_matches():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/push/users/user-1/settings",
            json={"data": {"theme": "dark"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        # First pull to get ETag
        resp1 = await client.get("/pull/users/user-1/settings")
        etag = resp1.headers["etag"]

        # Second pull with If-None-Match
        resp2 = await client.get(
            "/pull/users/user-1/settings",
            headers={"If-None-Match": etag},
        )
    assert resp2.status_code == 304


def _build_field_perm_app() -> tuple[FastAPI, MemoryObjectStore]:
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="profile",
                storagePath="users/{identity}/profile",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
                fieldPermissions={"secret": FieldPermission(readRoles=["admin"])},
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=[])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


@pytest.mark.asyncio
async def test_etag_conditional_survives_field_permission_filtering():
    """A field-permission collection still emits its ETag and honors If-None-Match.

    The pull handler rebuilds the response to strip restricted fields; that rebuild now
    carries the hash-derived ETag (and Cache-Control) forward, so conditional caching (304)
    keeps working for exactly the collections (profiles, etc.) most likely to be polled.
    Pins parity with the TS server, which filters `data` in place and never loses the ETag.
    """
    app, _ = _build_field_perm_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/push/users/user-1/profile",
            json={"data": {"theme": "dark"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        resp1 = await client.get("/pull/users/user-1/profile")
        etag = resp1.headers.get("etag")
        assert etag is not None  # the field-filter rebuild must not drop the ETag
        resp2 = await client.get(
            "/pull/users/user-1/profile", headers={"If-None-Match": etag}
        )
    assert resp2.status_code == 304


@pytest.mark.asyncio
async def test_200_when_etag_mismatch():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/push/users/user-1/settings",
            json={"data": {"theme": "dark"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        resp = await client.get(
            "/pull/users/user-1/settings",
            headers={"If-None-Match": '"stale-hash"'},
        )
    assert resp.status_code == 200
