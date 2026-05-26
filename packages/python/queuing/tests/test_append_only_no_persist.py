"""Tests for appendOnly+persist=false collection (replaces queueOnly), driven via the queuing plugin."""

import json

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import (
    SyncConfig,
    CollectionConfig,
    AppendOnlyConfig,
)
from starfish_server.config.validate import validate_config
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from starfish_queuing import MemoryQueue, QueueConfig, create_queuing_server_plugin

from tests.helpers import MemoryObjectStore


def _make_col(**overrides) -> CollectionConfig:
    defaults = dict(
        name="events",
        storagePath="events/{eventId}",
        readRoles=["public"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
    )
    defaults.update(overrides)
    return CollectionConfig(**defaults)


def _build_app(col: CollectionConfig, queue_collections: dict[str, QueueConfig] | None = None):
    store = MemoryObjectStore()
    q = MemoryQueue()
    config = SyncConfig(version=1, collections=[col])

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["admin"])

    plugin = create_queuing_server_plugin(queue=q, collections=queue_collections or {})
    router = create_sync_router(
        SyncRouterOptions(
            store=store, config=config, role_resolver=role_resolver, plugins=[plugin],
        ),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store, q


async def _push(client: AsyncClient, path: str = "/push/events/evt-1", base_hash=None):
    return await client.post(
        path,
        json={"data": {"type": "click"}, "baseHash": base_hash},
        headers={"content-type": "application/json"},
    )


@pytest.mark.asyncio
async def test_push_returns_hash_and_timestamp():
    app, _, _ = _build_app(_make_col(appendOnly=AppendOnlyConfig(type="by_timestamp", persist=False, requireAuthorSignature=False)))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client)
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body["hash"], str)
    assert len(body["hash"]) == 64  # SHA-256 hex
    assert isinstance(body["timestamp"], int)


@pytest.mark.asyncio
async def test_does_not_write_to_storage():
    app, store, _ = _build_app(_make_col(appendOnly=AppendOnlyConfig(type="by_timestamp", persist=False, requireAuthorSignature=False)))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client)
    stored = await store.get_string("events/evt-1")
    assert stored is None


@pytest.mark.asyncio
async def test_pull_returns_empty_data():
    """Nothing stored → pull returns empty."""
    app, _, _ = _build_app(_make_col(appendOnly=AppendOnlyConfig(type="by_timestamp", persist=False, requireAuthorSignature=False)))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client)
        resp = await client.get("/pull/events/evt-1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"] == {}
    assert body["hash"] == ""


@pytest.mark.asyncio
async def test_accepts_any_base_hash():
    """No conflict detection — any baseHash is accepted."""
    app, _, _ = _build_app(_make_col(appendOnly=AppendOnlyConfig(type="by_timestamp", persist=False, requireAuthorSignature=False)))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client)
        resp = await _push(client, base_hash="arbitrary-wrong-hash")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_consistent_hash_for_same_data():
    app, _, _ = _build_app(_make_col(appendOnly=AppendOnlyConfig(type="by_timestamp", persist=False, requireAuthorSignature=False)))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp1 = await _push(client, "/push/events/evt-1")
        resp2 = await _push(client, "/push/events/evt-2")
    assert resp1.json()["hash"] == resp2.json()["hash"]


@pytest.mark.asyncio
async def test_publishes_queue_event():
    col = _make_col(appendOnly=AppendOnlyConfig(type="by_timestamp", persist=False, requireAuthorSignature=False))
    app, _, q = _build_app(col, {"events": QueueConfig(topic="events.created")})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client)
    push_body = resp.json()

    assert len(q.messages) == 1
    subject, payload = q.messages[0]
    msg = json.loads(payload)
    assert subject == "events.created"
    assert msg["collection"] == "events"
    assert msg["hash"] == push_body["hash"]
    assert msg["timestamp"] == push_body["timestamp"]


@pytest.mark.asyncio
async def test_push_accepted_without_queue_configured():
    """appendOnly+persist=false without a configured queue: ephemeral (no storage, no event)."""
    col = _make_col(appendOnly=AppendOnlyConfig(type="by_timestamp", persist=False, requireAuthorSignature=False))
    app, _, q = _build_app(col)  # no queue_collections
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client)
    assert resp.status_code == 200
    assert len(q.messages) == 0


@pytest.mark.asyncio
async def test_still_validates_missing_data_field():
    app, _, _ = _build_app(_make_col(appendOnly=AppendOnlyConfig(type="by_timestamp", persist=False, requireAuthorSignature=False)))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/events/evt-1",
            json={"baseHash": None},
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 400


def test_valid_append_only_no_persist_collection():
    errors = validate_config(SyncConfig(version=1, collections=[_make_col(appendOnly=AppendOnlyConfig(type="by_timestamp", persist=False, requireAuthorSignature=False))]))
    assert errors == []


def test_append_only_binary_collection_rejected():
    col = _make_col(appendOnly=AppendOnlyConfig(type="by_timestamp", persist=False, requireAuthorSignature=False), allowedMimeTypes=["image/png"])
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert any("appendOnly cannot be used with binary collections" in e for e in errors)


def test_append_only_pullonly_rejected():
    col = _make_col(appendOnly=AppendOnlyConfig(type="by_timestamp", persist=False, requireAuthorSignature=False), pull_only=True)
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert any("appendOnly cannot be used with pullOnly" in e for e in errors)
