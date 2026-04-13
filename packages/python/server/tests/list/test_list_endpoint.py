"""Tests for the GET /list/... endpoint."""

import json

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.config.validate import validate_config
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from tests.helpers import MemoryObjectStore


def _make_col(**overrides) -> CollectionConfig:
    defaults = dict(
        name="chat",
        storagePath="chats/{groupId}/{day}",
        readRoles=["member"],
        writeRoles=["member"],
        encryption="none",
        maxBodyBytes=65536,
        listable=True,
    )
    defaults.update(overrides)
    return CollectionConfig(**defaults)


def _build_app(col: CollectionConfig, identity: str = "user-1", roles: list[str] | None = None):
    if roles is None:
        roles = ["member"]
    store = MemoryObjectStore()
    config = SyncConfig(version=1, collections=[col])

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=roles)

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


async def _push(client: AsyncClient, path: str, data: dict | None = None) -> None:
    if data is None:
        data = {"msg": "hello"}
    resp = await client.post(
        path,
        json={"data": data, "baseHash": None},
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 200


# ── Happy-path tests ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_returns_empty_when_no_documents():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/list/chats/group-1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["items"] == []
    assert body["hasMore"] is False


@pytest.mark.asyncio
async def test_lists_single_document():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/chats/group-1/2026-04-13")
        resp = await client.get("/list/chats/group-1")
    assert resp.status_code == 200
    body = resp.json()
    assert "2026-04-13" in body["items"]
    assert body["hasMore"] is False


@pytest.mark.asyncio
async def test_lists_multiple_documents_sorted():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for day in ["2026-04-13", "2026-04-12", "2026-04-11"]:
            await _push(client, f"/push/chats/group-1/{day}")
        resp = await client.get("/list/chats/group-1")
    body = resp.json()
    assert body["items"] == ["2026-04-11", "2026-04-12", "2026-04-13"]


@pytest.mark.asyncio
async def test_does_not_mix_groups():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/chats/group-1/2026-04-13")
        await _push(client, "/push/chats/group-2/2026-04-13")
        resp = await client.get("/list/chats/group-1")
    body = resp.json()
    assert body["items"] == ["2026-04-13"]


# ── Pagination ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_limit_parameter():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for i in range(1, 6):
            await _push(client, f"/push/chats/group-1/day-{i:03d}")
        resp = await client.get("/list/chats/group-1?limit=3")
    body = resp.json()
    assert len(body["items"]) == 3
    assert body["hasMore"] is True


@pytest.mark.asyncio
async def test_cursor_pagination():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for i in range(1, 6):
            await _push(client, f"/push/chats/group-1/day-{i:03d}")

        resp1 = await client.get("/list/chats/group-1?limit=3")
        body1 = resp1.json()
        assert len(body1["items"]) == 3
        assert body1["hasMore"] is True

        last_item = body1["items"][-1]
        resp2 = await client.get(f"/list/chats/group-1?limit=3&after={last_item}")
        body2 = resp2.json()
        assert len(body2["items"]) == 2
        assert body2["hasMore"] is False

        all_items = body1["items"] + body2["items"]
        assert len(set(all_items)) == 5


@pytest.mark.asyncio
async def test_invalid_limit_returns_400():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/list/chats/group-1?limit=abc")
    assert resp.status_code == 400


# ── Auth ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_returns_403_without_required_role():
    app, _ = _build_app(_make_col(), roles=["viewer"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/list/chats/group-1")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_public_access_works():
    col = _make_col(readRoles=["public"], writeRoles=["public"])
    store = MemoryObjectStore()
    config = SyncConfig(version=1, collections=[col])

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="", roles=[])

    router = create_sync_router(SyncRouterOptions(store=store, config=config, role_resolver=role_resolver))
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/chats/group-1/2026-04-13")
        resp = await client.get("/list/chats/group-1")
    assert resp.status_code == 200
    assert "2026-04-13" in resp.json()["items"]


@pytest.mark.asyncio
async def test_self_role_granted_on_list_with_identity_in_prefix():
    """When {identity} is in the prefix path, self role is still granted."""
    col = CollectionConfig(
        name="buckets",
        storagePath="data/{identity}/{bucket}",
        readRoles=["self"],
        writeRoles=["self"],
        encryption="none",
        maxBodyBytes=65536,
        listable=True,
    )
    store = MemoryObjectStore()
    config = SyncConfig(version=1, collections=[col])

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="alice", roles=[])

    router = create_sync_router(SyncRouterOptions(store=store, config=config, role_resolver=role_resolver))
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/data/alice/notes")
        resp = await client.get("/list/data/alice")
    assert resp.status_code == 200
    assert "notes" in resp.json()["items"]


# ── Single-param storagePath ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_single_path_param():
    col = CollectionConfig(
        name="notes",
        storagePath="notes/{userId}",
        readRoles=["admin"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
        listable=True,
    )
    app, _ = _build_app(col, roles=["admin"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/notes/alice")
        await _push(client, "/push/notes/bob")
        resp = await client.get("/list/notes")
    assert resp.status_code == 200
    assert sorted(resp.json()["items"]) == ["alice", "bob"]


# ── Namespace support ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_in_namespace():
    col = _make_col()
    store = MemoryObjectStore()
    config = SyncConfig(version=1, collections=[], namespaces={"v2": {"collections": [col]}})

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["member"])

    router = create_sync_router(SyncRouterOptions(store=store, config=config, role_resolver=role_resolver))
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/v2/push/chats/group-1/2026-04-13")
        resp = await client.get("/v2/list/chats/group-1")
    assert resp.status_code == 200
    assert "2026-04-13" in resp.json()["items"]


# ── Config validation ─────────────────────────────────────────────────────────

def test_valid_listable_passes():
    errors = validate_config(SyncConfig(version=1, collections=[_make_col()]))
    assert errors == []


def test_listable_without_params_rejected():
    col = CollectionConfig(
        name="settings",
        storagePath="settings",
        readRoles=["admin"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
        listable=True,
    )
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert any("at least one path parameter" in e for e in errors)


def test_listable_with_static_last_segment_rejected():
    col = CollectionConfig(
        name="log",
        storagePath="users/{userId}/log",
        readRoles=["admin"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
        listable=True,
    )
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert any("last storagePath segment" in e for e in errors)


def test_listable_with_queueonly_rejected():
    col = _make_col(queue_only=True)
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert any("listable cannot be used with queueOnly" in e for e in errors)
