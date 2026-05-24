"""Tests for TTL expiration and field-level permissions in the router."""

import time
import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig, FieldPermission
from starfish_server.router.route_builder import create_sync_router, SyncRouterOptions, AuthResult
from tests.helpers import MemoryObjectStore


def _make_app_with_enricher(
    config: SyncConfig,
    identity: str = "user-1",
    roles: list[str] | None = None,
    role_enricher=None,
) -> tuple[FastAPI, MemoryObjectStore]:
    store = MemoryObjectStore()

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=roles or [])

    router = create_sync_router(
        SyncRouterOptions(
            store=store,
            config=config,
            role_resolver=role_resolver,
            role_enricher=role_enricher,
        ),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


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


@pytest.mark.asyncio
async def test_ttl_pull_zeros_hash_for_expired_document():
    """An expired document must return hash='' alongside empty data.
    Without the fix, hash retains the real stored hash — a client that pushes
    back with that hash passes the baseHash check and overwrites the doc with
    empty data, silently clobbering content."""
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
        await client.post(
            "/push/users/user-1/settings",
            json={"data": {"secret": "value"}, "baseHash": None},
        )
        time.sleep(0.01)
        pull_resp = await client.get("/pull/users/user-1/settings")
    assert pull_resp.status_code == 200
    assert pull_resp.json()["hash"] == ""


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
async def test_field_permissions_write_treats_explicit_null_as_a_write():
    """Setting a restricted field to ``null`` is still a write — presence, not truthiness.

    The guard keys on ``field_name in data``, so a non-privileged user cannot blank out
    (or no-op-touch) an admin-only field by sending ``null``; only OMITTING the key avoids
    the check. Pins that ``null`` does not slip past field-level write permissions.
    """
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
            json={"data": {"adminFlag": None, "theme": "dark"}, "baseHash": None},
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


# ---------------------------------------------------------------------------
# "public" role in field-level read permissions
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_field_permissions_public_read_role_visible_to_authenticated_user():
    """A field with readRoles=["public"] must be visible to authenticated users.

    Previously, Python never added ROLE_PUBLIC to effective_roles for
    authenticated requests, so "public" fields were stripped for authenticated
    users — they saw less than anonymous callers.
    """
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
                fieldPermissions={"bio": FieldPermission(readRoles=["public"])},
            ),
        ],
    )
    app, _ = _make_app(config, identity="user-1", roles=[])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/push/users/user-1/profile",
            json={"data": {"name": "Alice", "bio": "Hello!"}, "baseHash": None},
        )
        pull_resp = await client.get("/pull/users/user-1/profile")

    assert pull_resp.status_code == 200
    data = pull_resp.json()["data"]
    assert data["name"] == "Alice"
    assert "bio" in data, "field with readRoles=['public'] must be visible to authenticated users"
    assert data["bio"] == "Hello!"


# ---------------------------------------------------------------------------
# roleEnricher exception handling
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_role_enricher_exception_returns_500_not_crash():
    """A crashing roleEnricher must return a structured 500, not an unhandled exception."""
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

    async def crashing_enricher(auth: AuthResult, params: dict) -> list[str]:
        raise RuntimeError("Enricher exploded")

    app, _ = _make_app_with_enricher(config, identity="user-1", roles=[], role_enricher=crashing_enricher)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/users/user-1/settings")

    # Must return a structured error response, not an unhandled 500 with traceback
    assert resp.status_code == 500
    body = resp.json()
    assert "error" in body


@pytest.mark.asyncio
async def test_field_write_public_role_allows_authenticated_user():
    # A field whose writeRoles is ["public"] means "anyone may write it". An
    # authenticated user (role "self", not the literal "public") should be allowed.
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
                fieldPermissions={"openField": FieldPermission(writeRoles=["public"])},
            ),
        ],
    )
    app, _ = _make_app(config, identity="user-1", roles=["self"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"openField": "anyone-can-write"}, "baseHash": None},
        )
    assert resp.status_code == 200
