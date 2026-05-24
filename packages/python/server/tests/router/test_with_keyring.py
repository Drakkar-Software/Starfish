"""Tests for the optional ?withKeyring=1 pull optimization."""

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig
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
                name="notes",
                storagePath="users/{identity}/notes",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="delegated",
                maxBodyBytes=65536,
            ),
            CollectionConfig(
                name="notes_keyring",
                storagePath="users/{identity}/notes/_keyring",
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


async def _push(client: AsyncClient, path: str, data: dict) -> str:
    resp = await client.post(
        path,
        json={"data": data, "baseHash": None},
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["hash"]


@pytest.mark.asyncio
async def test_default_pull_has_no_keyring_field():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/users/user-1/notes", {"_encrypted": "ct", "_epoch": 1})
        await _push(client, "/push/users/user-1/notes/_keyring", {"v": 1, "currentEpoch": 1})

        resp = await client.get("/pull/users/user-1/notes")
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"] == {"_encrypted": "ct", "_epoch": 1}
        assert "keyring" not in body


@pytest.mark.asyncio
async def test_with_keyring_returns_data_and_keyring():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/users/user-1/notes", {"_encrypted": "ct", "_epoch": 3})
        await _push(
            client,
            "/push/users/user-1/notes/_keyring",
            {"v": 1, "currentEpoch": 3, "epochs": {"3": {"wraps": {}}}},
        )

        resp = await client.get("/pull/users/user-1/notes?withKeyring=1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"] == {"_encrypted": "ct", "_epoch": 3}
        kr = body["keyring"]
        assert kr is not None
        assert kr["data"] == {"v": 1, "currentEpoch": 3, "epochs": {"3": {"wraps": {}}}}
        assert isinstance(kr["hash"], str) and kr["hash"]
        assert isinstance(kr["timestamp"], int)
        # Author fields are dropped from the keyring projection.
        assert "authorPubkey" not in kr
        assert "authorSignature" not in kr


@pytest.mark.asyncio
async def test_with_keyring_returns_null_when_missing():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/users/user-1/notes", {"_encrypted": "ct", "_epoch": 1})

        resp = await client.get("/pull/users/user-1/notes?withKeyring=1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"] == {"_encrypted": "ct", "_epoch": 1}
        assert body["keyring"] is None


@pytest.mark.asyncio
async def test_with_keyring_true_string_is_on():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/users/user-1/notes", {"_encrypted": "ct", "_epoch": 1})
        await _push(client, "/push/users/user-1/notes/_keyring", {"v": 1, "currentEpoch": 1})

        resp = await client.get("/pull/users/user-1/notes?withKeyring=true")
        assert resp.status_code == 200
        body = resp.json()
        assert body["keyring"] is not None
        assert body["keyring"]["data"]["v"] == 1


@pytest.mark.asyncio
async def test_with_keyring_zero_is_off():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/users/user-1/notes", {"_encrypted": "ct", "_epoch": 1})
        await _push(client, "/push/users/user-1/notes/_keyring", {"v": 1, "currentEpoch": 1})

        resp = await client.get("/pull/users/user-1/notes?withKeyring=0")
        assert resp.status_code == 200
        body = resp.json()
        assert "keyring" not in body


@pytest.mark.asyncio
async def test_with_keyring_degrades_gracefully_on_store_error():
    """A store error reading the sibling keyring yields keyring=None, not HTTP 500.

    Models a filesystem store raising (e.g. NotADirectoryError) when the data path
    is a leaf file and the app keeps its keyring in a separate namespace. The
    optimization must degrade, never crash the pull.
    """

    class _RaisingKeyringStore(MemoryObjectStore):
        async def get_string(self, key, *, context=None):
            if key.endswith("/_keyring"):
                raise NotADirectoryError(key)
            return await super().get_string(key, context=context)

    store = _RaisingKeyringStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="notes",
                storagePath="users/{identity}/notes",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="delegated",
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
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/users/user-1/notes", {"_encrypted": "ct", "_epoch": 1})
        resp = await client.get("/pull/users/user-1/notes?withKeyring=1")
        assert resp.status_code == 200
        assert resp.json()["keyring"] is None


# --- ?withKeyring=1 must honour the caller's cap-cert scope ------------------
#
# The keyring document is owner-only; a cap that denies ``<col>/_keyring`` must
# not be able to read it via the withKeyring sibling shortcut.


def _build_scoped_app(
    scope_paths: list[str] | None, data_path: str = "users/{identity}/notes"
) -> tuple[FastAPI, MemoryObjectStore]:
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="notes",
                storagePath=data_path,
                readRoles=["self"],
                writeRoles=["self"],
                encryption="delegated",
                maxBodyBytes=65536,
            ),
            CollectionConfig(
                name="notes_keyring",
                storagePath=f"{data_path}/_keyring",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["self"], scope_paths=scope_paths)

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


@pytest.mark.asyncio
async def test_with_keyring_omitted_when_cap_scope_denies_keyring():
    """A writer-shaped scope that denies ``_keyring`` must not leak it."""
    app, _ = _build_scoped_app(
        ["users/user-1/notes/**", "!users/user-1/notes/_keyring"]
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/users/user-1/notes", {"_encrypted": "ct"})
        await _push(client, "/push/users/user-1/notes/_keyring", {"v": 1, "currentEpoch": 1})

        resp = await client.get("/pull/users/user-1/notes?withKeyring=1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"] == {"_encrypted": "ct"}
        # Owner-only keyring is NOT leaked despite the document existing.
        assert body.get("keyring") is None


@pytest.mark.asyncio
async def test_with_keyring_included_when_cap_scope_allows_keyring():
    """An admin-shaped scope (no deny) still gets the keyring optimization."""
    app, _ = _build_scoped_app(["users/user-1/notes/**"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/users/user-1/notes", {"_encrypted": "ct"})
        await _push(client, "/push/users/user-1/notes/_keyring", {"v": 1, "currentEpoch": 1})

        resp = await client.get("/pull/users/user-1/notes?withKeyring=1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["keyring"] is not None
        assert body["keyring"]["data"]["v"] == 1


@pytest.mark.asyncio
async def test_with_keyring_omitted_for_root_allow_keyring_deny_scope():
    """Exact exploit shape: a custom scope allows the collection root and its
    children but denies the root ``_keyring``. The sibling shortcut must not
    return the keyring even though the data pull itself is allowed."""
    app, _ = _build_scoped_app(["notes", "notes/**", "!notes/_keyring"], data_path="notes")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/notes", {"_encrypted": "ct"})
        await _push(client, "/push/notes/_keyring", {"v": 9})

        resp = await client.get("/pull/notes?withKeyring=1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"] == {"_encrypted": "ct"}
        assert body.get("keyring") is None


@pytest.mark.asyncio
async def test_with_keyring_included_when_resolver_has_no_scope():
    """Pure role-based auth (scope_paths=None) keeps the optimization working."""
    app, _ = _build_scoped_app(None)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/users/user-1/notes", {"_encrypted": "ct"})
        await _push(client, "/push/users/user-1/notes/_keyring", {"v": 7, "currentEpoch": 1})

        resp = await client.get("/pull/users/user-1/notes?withKeyring=1")
        assert resp.status_code == 200
        body = resp.json()
        assert body["keyring"] is not None
        assert body["keyring"]["data"]["v"] == 7
