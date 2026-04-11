"""Tests for TTL expiration and field-level permissions in the router."""

import time
import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig, FieldPermission
from starfish_server.router.route_builder import create_sync_router, SyncRouterOptions, AuthResult
from tests.helpers import MemoryObjectStore


def _make_app(
    config: SyncConfig,
    identity: str = "user-1",
    roles: list[str] | None = None,
) -> tuple[FastAPI, MemoryObjectStore]:
    store = MemoryObjectStore()

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=roles or [])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


# ---------------------------------------------------------------------------
# TTL enforcement in pull handler
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ttl_pull_returns_empty_data_for_expired_document():
    """An expired document should return empty data on pull."""
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
                ttlMs=1,  # 1 ms TTL — expires immediately
            ),
        ],
    )
    app, _ = _make_app(config)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Push some data
        push_resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"secret": "value"}, "baseHash": None},
        )
        assert push_resp.status_code == 200

        # Sleep briefly to ensure TTL has elapsed
        time.sleep(0.01)

        pull_resp = await client.get("/pull/users/user-1/settings")
    assert pull_resp.status_code == 200
    assert pull_resp.json()["data"] == {}


@pytest.mark.asyncio
async def test_ttl_pull_returns_data_for_non_expired_document():
    """A fresh document (not expired) should return its data normally."""
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
                ttlMs=3_600_000,  # 1 hour TTL
            ),
        ],
    )
    app, _ = _make_app(config)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/push/users/user-1/settings",
            json={"data": {"theme": "dark"}, "baseHash": None},
        )
        pull_resp = await client.get("/pull/users/user-1/settings")
    assert pull_resp.status_code == 200
    assert pull_resp.json()["data"] == {"theme": "dark"}


@pytest.mark.asyncio
async def test_ttl_not_set_returns_data_normally():
    """Collections without ttlMs should behave normally regardless of age."""
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
                # No ttlMs set
            ),
        ],
    )
    app, _ = _make_app(config)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/push/users/user-1/settings",
            json={"data": {"x": 1}, "baseHash": None},
        )
        pull_resp = await client.get("/pull/users/user-1/settings")
    assert pull_resp.status_code == 200
    assert pull_resp.json()["data"] == {"x": 1}


# ---------------------------------------------------------------------------
# Field-level read permissions
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_field_permissions_read_hides_restricted_field_for_non_privileged():
    """A field with readRoles should be hidden from users without those roles."""
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
    app, _ = _make_app(config, identity="user-1", roles=[])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Push data including the restricted field
        await client.post(
            "/push/users/user-1/profile",
            json={"data": {"name": "Alice", "secret": "hidden"}, "baseHash": None},
        )
        pull_resp = await client.get("/pull/users/user-1/profile")

    assert pull_resp.status_code == 200
    data = pull_resp.json()["data"]
    assert data["name"] == "Alice"
    assert "secret" not in data


@pytest.mark.asyncio
async def test_field_permissions_read_shows_field_for_privileged_user():
    """A user with the required readRole should see the restricted field."""
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="profile",
                storagePath="users/{identity}/profile",
                readRoles=["admin"],
                writeRoles=["admin"],
                encryption="none",
                maxBodyBytes=65536,
                fieldPermissions={"secret": FieldPermission(readRoles=["admin"])},
            ),
        ],
    )
    app, _ = _make_app(config, identity="user-1", roles=["admin"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/push/users/user-1/profile",
            json={"data": {"name": "Alice", "secret": "visible"}, "baseHash": None},
        )
        pull_resp = await client.get("/pull/users/user-1/profile")

    assert pull_resp.status_code == 200
    data = pull_resp.json()["data"]
    assert data["secret"] == "visible"


# ---------------------------------------------------------------------------
# Field-level write permissions
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_field_permissions_write_rejects_forbidden_field():
    """A user without the required writeRole should not be able to write a restricted field."""
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
                fieldPermissions={"adminFlag": FieldPermission(writeRoles=["admin"])},
            ),
        ],
    )
    app, _ = _make_app(config, identity="user-1", roles=[])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"adminFlag": True, "theme": "dark"}, "baseHash": None},
        )
    assert resp.status_code == 403
    assert "adminFlag" in resp.json()["error"]


@pytest.mark.asyncio
async def test_field_permissions_write_allows_other_fields_without_restriction():
    """Writing fields that have no writeRoles restriction should succeed."""
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
                fieldPermissions={"adminFlag": FieldPermission(writeRoles=["admin"])},
            ),
        ],
    )
    app, _ = _make_app(config, identity="user-1", roles=[])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"theme": "dark"}, "baseHash": None},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_field_permissions_write_allowed_for_privileged_user():
    """A user with the required writeRole should be able to write a restricted field."""
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="settings",
                storagePath="users/{identity}/settings",
                readRoles=["self", "admin"],
                writeRoles=["self", "admin"],
                encryption="none",
                maxBodyBytes=65536,
                fieldPermissions={"adminFlag": FieldPermission(writeRoles=["admin"])},
            ),
        ],
    )
    app, _ = _make_app(config, identity="user-1", roles=["admin"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"adminFlag": True, "theme": "dark"}, "baseHash": None},
        )
    assert resp.status_code == 200
