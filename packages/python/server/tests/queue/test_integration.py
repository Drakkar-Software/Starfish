"""Integration tests — queue events published on push through the FastAPI router."""

import json

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig, QueueConfig
from starfish_server.queue.memory import MemoryQueue
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from tests.helpers import MemoryObjectStore


def _build_app(
    collections: list[CollectionConfig],
    queue: MemoryQueue | None = None,
) -> tuple[FastAPI, MemoryObjectStore, MemoryQueue]:
    store = MemoryObjectStore()
    q = queue or MemoryQueue()
    config = SyncConfig(version=1, collections=collections)

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["admin", "self"])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver, queue=q),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store, q


def _col_with_queue(**queue_kwargs) -> CollectionConfig:
    return CollectionConfig(
        name="posts",
        storagePath="posts/{postId}",
        readRoles=["public"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
        queue=QueueConfig(**queue_kwargs) if queue_kwargs or queue_kwargs == {} else QueueConfig(),
    )


def _col_without_queue() -> CollectionConfig:
    return CollectionConfig(
        name="posts",
        storagePath="posts/{postId}",
        readRoles=["public"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
    )


async def _push(client: AsyncClient, path: str = "/push/posts/abc") -> dict:
    resp = await client.post(
        path,
        json={"data": {"title": "Hello"}, "baseHash": None},
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 200
    return resp.json()


@pytest.mark.asyncio
async def test_push_publishes_queue_event():
    app, store, q = _build_app([_col_with_queue()])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        push_body = await _push(client)

    assert len(q.messages) == 1
    subject, payload = q.messages[0]
    msg = json.loads(payload)
    assert subject == "posts"  # default topic = collection name
    assert msg["collection"] == "posts"
    assert msg["hash"] == push_body["hash"]
    assert msg["timestamp"] == push_body["timestamp"]
    assert "params" not in msg


@pytest.mark.asyncio
async def test_push_no_queue_config_no_event():
    app, store, q = _build_app([_col_without_queue()])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client)

    assert len(q.messages) == 0


@pytest.mark.asyncio
async def test_custom_topic():
    col = _col_with_queue(topic="custom.topic")
    app, store, q = _build_app([col])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client)

    assert q.messages[0][0] == "custom.topic"


@pytest.mark.asyncio
async def test_include_params():
    col = _col_with_queue(include_params=True)
    app, store, q = _build_app([col])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/posts/my-post-id")

    msg = json.loads(q.messages[0][1])
    assert msg["params"] == {"postId": "my-post-id"}


@pytest.mark.asyncio
async def test_no_include_params_by_default():
    col = _col_with_queue()
    app, store, q = _build_app([col])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client)

    msg = json.loads(q.messages[0][1])
    assert "params" not in msg


@pytest.mark.asyncio
async def test_no_event_on_conflict():
    """Queue event should NOT be published when push returns 409 (hash mismatch)."""
    col = _col_with_queue()
    app, store, q = _build_app([col])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # First push succeeds
        await _push(client)
        q.messages.clear()

        # Second push with wrong baseHash → 409
        resp = await client.post(
            "/push/posts/abc",
            json={"data": {"title": "Updated"}, "baseHash": "wrong-hash"},
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 409

    assert len(q.messages) == 0


@pytest.mark.asyncio
async def test_queue_config_coercion_true():
    """'queue: true' in JSON should enable queue with defaults."""
    col = CollectionConfig(
        name="test",
        storagePath="test/doc",
        readRoles=["public"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
        queue=True,  # type: ignore[arg-type]
    )
    assert col.queue is not None
    assert col.queue.topic is None
    assert col.queue.include_params is False


@pytest.mark.asyncio
async def test_queue_config_coercion_false():
    """'queue: false' in JSON should disable queue."""
    col = CollectionConfig(
        name="test",
        storagePath="test/doc",
        readRoles=["public"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
        queue=False,  # type: ignore[arg-type]
    )
    assert col.queue is None
