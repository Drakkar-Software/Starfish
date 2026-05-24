"""Integration tests — the queuing plugin publishes events on push through the FastAPI router."""

import json

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from starfish_queuing import (
    MemoryQueue,
    QueueConfig,
    create_queuing_server_plugin,
)
from starfish_queuing.base import AbstractQueue
from starfish_queuing.publish import publish_change_event
from starfish_protocol.plugins import WriteEvent

from tests.helpers import MemoryObjectStore


def _build_app(
    collections: list[CollectionConfig],
    queue_collections: dict[str, QueueConfig] | None = None,
    queue: AbstractQueue | None = None,
) -> tuple[FastAPI, MemoryObjectStore, AbstractQueue]:
    store = MemoryObjectStore()
    q = queue or MemoryQueue()
    config = SyncConfig(version=1, collections=collections)

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["admin", "self"])

    plugin = create_queuing_server_plugin(queue=q, collections=queue_collections or {})
    router = create_sync_router(
        SyncRouterOptions(
            store=store, config=config, role_resolver=role_resolver, plugins=[plugin],
        ),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store, q


def _col(name: str = "posts", storage_path: str = "posts/{postId}", **overrides) -> CollectionConfig:
    return CollectionConfig(
        name=name,
        storagePath=storage_path,
        readRoles=["public"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
        **overrides,
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
    app, store, q = _build_app([_col()], {"posts": QueueConfig()})
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
async def test_push_collection_not_configured_no_event():
    app, store, q = _build_app([_col()], {})  # "posts" not in plugin map
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client)

    assert len(q.messages) == 0


@pytest.mark.asyncio
async def test_custom_topic():
    app, store, q = _build_app([_col()], {"posts": QueueConfig(topic="custom.topic")})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client)

    assert q.messages[0][0] == "custom.topic"


@pytest.mark.asyncio
async def test_include_params():
    app, store, q = _build_app([_col()], {"posts": QueueConfig(include_params=True)})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/posts/my-post-id")

    msg = json.loads(q.messages[0][1])
    assert msg["params"] == {"postId": "my-post-id"}


@pytest.mark.asyncio
async def test_no_include_params_by_default():
    app, store, q = _build_app([_col()], {"posts": QueueConfig()})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client)

    msg = json.loads(q.messages[0][1])
    assert "params" not in msg


@pytest.mark.asyncio
async def test_no_event_on_conflict():
    """Queue event should NOT be published when push returns 409 (hash mismatch)."""
    app, store, q = _build_app([_col()], {"posts": QueueConfig()})
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
async def test_include_body():
    app, store, q = _build_app([_col()], {"posts": QueueConfig(include_body=True)})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/posts/my-post-id")

    msg = json.loads(q.messages[0][1])
    assert msg["body"] == {"title": "Hello"}


@pytest.mark.asyncio
async def test_no_include_body_by_default():
    app, store, q = _build_app([_col()], {"posts": QueueConfig()})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client)

    msg = json.loads(q.messages[0][1])
    assert "body" not in msg


@pytest.mark.asyncio
async def test_include_body_and_params_together():
    app, store, q = _build_app(
        [_col()], {"posts": QueueConfig(include_body=True, include_params=True)},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/posts/post-42")

    msg = json.loads(q.messages[0][1])
    assert msg["body"] == {"title": "Hello"}
    assert msg["params"] == {"postId": "post-42"}


@pytest.mark.asyncio
async def test_binary_collection_include_body_never_emits_body():
    col = _col(
        name="avatar",
        storage_path="users/{userId}/avatar",
        allowedMimeTypes=["image/png"],
    )
    app, store, q = _build_app([col], {"avatar": QueueConfig(include_body=True)})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/avatar",
            content=b"\x89PNG",
            headers={"content-type": "image/png"},
        )
        assert resp.status_code == 200

    assert len(q.messages) == 1
    msg = json.loads(q.messages[0][1])
    assert "body" not in msg
    assert msg["collection"] == "avatar"


@pytest.mark.asyncio
async def test_queue_failure_does_not_break_push():
    """A queue publish error must not propagate to the client."""

    class FailingQueue(AbstractQueue):
        async def publish(self, subject: str, payload: bytes) -> None:
            raise RuntimeError("NATS connection lost")

    app, store, q = _build_app([_col()], {"posts": QueueConfig()}, queue=FailingQueue())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        push_body = await _push(client)

    assert "hash" in push_body
    assert "timestamp" in push_body


@pytest.mark.asyncio
async def test_bundle_collection_include_body_emits_body():
    col = _col(
        name="prefs",
        storage_path="users/{userId}/data",
        bundle="userdata",
    )
    app, store, q = _build_app([col], {"prefs": QueueConfig(include_body=True)})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/data/prefs",
            json={"data": {"theme": "dark"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 200

    assert len(q.messages) == 1
    msg = json.loads(q.messages[0][1])
    assert msg["collection"] == "prefs"
    assert msg["body"] == {"theme": "dark"}


@pytest.mark.asyncio
async def test_empty_topic_falls_back_to_collection_name():
    # Cross-language divergence on a reachable, user-settable config field.
    # Python uses `config.topic or event.collection` (publish.py), which coalesces
    # an empty-string topic to the collection name — the safe behaviour, since an
    # empty broker subject is a footgun. TS uses `cfg.topic ?? event.collection`,
    # which keeps "" verbatim and publishes to subject "". This test pins the
    # convergent behaviour; the TS side is pinned as it.fails in plugin.test.ts.
    app, store, q = _build_app([_col()], {"posts": QueueConfig(topic="")})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client)

    assert q.messages[0][0] == "posts"


@pytest.mark.asyncio
async def test_omits_params_when_storage_path_has_no_path_params():
    # include_params gate is `if config.include_params and event.params:`, so an
    # empty params map (no `{…}` placeholders in storage_path) publishes no params.
    col = _col(name="config", storage_path="global/config")
    app, store, q = _build_app([col], {"config": QueueConfig(include_params=True)})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/global/config",
            json={"data": {"x": 1}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 200

    assert len(q.messages) == 1
    msg = json.loads(q.messages[0][1])
    assert "params" not in msg


@pytest.mark.asyncio
async def test_preserves_unicode_in_topic_and_body():
    # Path segments are charset-restricted (non-ASCII rejected at the door), so
    # unicode is probed on the reachable surfaces: config topic and JSON body.
    app, store, q = _build_app(
        [_col()], {"posts": QueueConfig(include_body=True, topic="更新.notify")},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/posts/post-1",
            json={"data": {"note": "Ñoño 🎉", "ключ": "значение"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 200

    assert len(q.messages) == 1
    subject, payload = q.messages[0]
    assert subject == "更新.notify"
    msg = json.loads(payload)
    assert msg["body"]["note"] == "Ñoño 🎉"
    assert msg["body"]["ключ"] == "значение"


@pytest.mark.asyncio
async def test_omits_a_none_body_handed_directly():
    # The Python gate is `if event.body is not None`, so a None body is OMITTED.
    # The server NEVER emits body=None as distinct from absent — route_builder.py
    # sets WriteEvent.body only when the pushed data is a dict, otherwise leaves it
    # None — so this is the absent case. TS's gate is `if (event.body !== undefined)`,
    # which INCLUDES an explicit null body; the difference is benign because neither
    # path is reached for a real document. Pinned (and flagged) so it's locked if
    # WriteEvent population ever changes. See plugin.test.ts for the TS side.
    q = MemoryQueue()
    event = WriteEvent(collection="posts", hash="h", timestamp=1, params={}, body=None)
    await publish_change_event(q, QueueConfig(include_body=True), event)

    assert len(q.messages) == 1
    msg = json.loads(q.messages[0][1])
    assert "body" not in msg
