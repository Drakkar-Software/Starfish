"""``QueueConfig.subject_param`` — per-resource subject derivation.

Two layers:

- **Integration** (HTTP push → plugin → queue): the param value from the route is
  appended to the subject, and it works even with ``include_params=False`` (the
  suffix is read from ``WriteEvent.params`` directly, not from the message body).
- **Direct** (``publish_change_event`` unit calls): the charset re-validation. An
  HTTP push can never deliver a metacharacter-bearing id — the upstream route/role
  gate rejects ``foo.bar`` before the plugin runs — so the ONLY way to exercise the
  queuing layer's defensive ``fullmatch`` (which guards against future gate drift)
  is to hand the plugin a bad id directly. A rejected id falls back to the base
  subject; it is never appended, so the broker never sees ``.`` ``*`` ``>``.
"""

import asyncio
import json

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_protocol.plugins import WriteEvent
from starfish_server.config.schema import CollectionConfig, SyncConfig
from starfish_server.router.route_builder import (
    AuthResult,
    SyncRouterOptions,
    create_sync_router,
)
from starfish_queuing import (
    DEFAULT_SAFE_ID,
    MemoryQueue,
    QueueConfig,
    create_queuing_server_plugin,
)
from starfish_queuing.base import AbstractQueue
from starfish_queuing.publish import publish_change_event

from tests.helpers import MemoryObjectStore


def _build_app(
    queue_collections: dict[str, QueueConfig],
    *,
    queue: AbstractQueue | None = None,
    storage_path: str = "posts/{postId}",
) -> tuple[FastAPI, AbstractQueue]:
    store = MemoryObjectStore()
    q = queue or MemoryQueue()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="posts",
                storagePath=storage_path,
                readRoles=["public"],
                writeRoles=["admin"],
                encryption="none",
                maxBodyBytes=65536,
            )
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["admin", "self"])

    plugin = create_queuing_server_plugin(queue=q, collections=queue_collections)
    router = create_sync_router(
        SyncRouterOptions(
            store=store, config=config, role_resolver=role_resolver, plugins=[plugin]
        )
    )
    app = FastAPI()
    app.include_router(router)
    return app, q


async def _push(app: FastAPI, path: str = "/push/posts/abc") -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            path,
            json={"data": {"title": "Hello"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 200, resp.text


def _publish_subject(config: QueueConfig, params: dict) -> str:
    """Run the plugin's publish path directly and return the resulting subject."""
    q = MemoryQueue()
    event = WriteEvent(collection="posts", hash="h", timestamp=1, params=params, body=None)
    asyncio.run(publish_change_event(q, config, event))
    assert len(q.messages) == 1
    return q.messages[0][0]


# ── integration: param appended to the subject ───────────────────────────────


@pytest.mark.asyncio
async def test_subject_param_appends_route_param():
    app, q = _build_app({"posts": QueueConfig(topic="posts.changed", subject_param="postId")})
    await _push(app, "/push/posts/my-post-id")
    assert q.messages[0][0] == "posts.changed.my-post-id"


@pytest.mark.asyncio
async def test_subject_param_independent_of_include_params():
    # include_params=False: the suffix still derives (read from WriteEvent.params,
    # not from the message body) — the key decoupling vs. the old re-parse pattern.
    app, q = _build_app(
        {"posts": QueueConfig(topic="posts.changed", subject_param="postId", include_params=False)}
    )
    await _push(app, "/push/posts/abc")
    subject, payload = q.messages[0]
    assert subject == "posts.changed.abc"
    assert "params" not in json.loads(payload)


@pytest.mark.asyncio
async def test_subject_param_defaults_to_collection_name_base():
    app, q = _build_app({"posts": QueueConfig(subject_param="postId")})  # no topic
    await _push(app, "/push/posts/abc")
    assert q.messages[0][0] == "posts.abc"


# ── direct: charset re-validation (defense-in-depth) ─────────────────────────


def test_default_pattern_is_the_safe_id_charset():
    assert DEFAULT_SAFE_ID.pattern == r"^[a-zA-Z0-9_-]+$"


@pytest.mark.parametrize(
    "bad_id",
    ["foo.bar", "foo*bar", "foo>bar", "foo bar", "foo\n", "\nfoo", "foo/bar", ""],
)
def test_metachar_id_falls_back_to_base_subject(bad_id):
    # A bad id is NEVER appended → the broker never sees a metacharacter token.
    subject = _publish_subject(
        QueueConfig(topic="posts.changed", subject_param="postId"), {"postId": bad_id}
    )
    assert subject == "posts.changed"


def test_missing_param_falls_back_to_base_subject():
    subject = _publish_subject(
        QueueConfig(topic="posts.changed", subject_param="postId"), {}
    )
    assert subject == "posts.changed"


def test_valid_id_is_appended_direct():
    subject = _publish_subject(
        QueueConfig(topic="posts.changed", subject_param="postId"), {"postId": "p_1-A"}
    )
    assert subject == "posts.changed.p_1-A"


def test_custom_subject_id_pattern_is_honored():
    import re

    # A stricter pattern (digits only) rejects an otherwise-safe alphanumeric id.
    cfg = QueueConfig(
        topic="posts.changed", subject_param="postId", subject_id_pattern=re.compile(r"^[0-9]+$")
    )
    assert _publish_subject(cfg, {"postId": "abc"}) == "posts.changed"
    assert _publish_subject(cfg, {"postId": "123"}) == "posts.changed.123"


def test_no_subject_param_leaves_subject_unchanged():
    subject = _publish_subject(QueueConfig(topic="posts.changed"), {"postId": "abc"})
    assert subject == "posts.changed"
