"""Tests for ReplicaManager — sync logic and write modes."""


import json
import time

import httpx
import pytest
import respx

from starfish_server.config.schema import (
    CollectionConfig,
    RemoteConfig,
    SyncTrigger,
    WriteMode,
)
from starfish_protocol.merge import deep_merge
from starfish_server.protocol.push import push
from starfish_server.replica.manager import ReplicaManager
from tests.helpers import MemoryObjectStore


def _make_col(
    write_mode: WriteMode = WriteMode.PULL_ONLY,
    sync_triggers: list[SyncTrigger] | None = None,
    on_pull_min_interval_ms: int | None = None,
) -> CollectionConfig:
    return CollectionConfig(
        name="featured",
        storage_path="posts/featured",
        read_roles=["public"],
        write_roles=[],
        encryption="none",
        max_body_bytes=65536,
        pull_only=True,
        remote=RemoteConfig(
            url="https://primary.example.com/v1",
            pull_path="/pull/posts/featured",
            push_path="/push/posts/featured",
            interval_ms=60_000,
            write_mode=write_mode,
            sync_triggers=sync_triggers or [SyncTrigger.SCHEDULED],
            on_pull_min_interval_ms=on_pull_min_interval_ms,
        ),
    )


def _primary_response(data: dict, hash_val: str = "abc123", timestamp: int = 1000) -> dict:
    return {"data": data, "hash": hash_val, "timestamp": timestamp}


# ── deep_merge ────────────────────────────────────────────────────────────


def test_deep_merge_remote_wins_scalar():
    result = deep_merge({"a": 1}, {"a": 2})
    assert result == {"a": 2}


def test_deep_merge_adds_remote_keys():
    result = deep_merge({"a": 1}, {"b": 2})
    assert result == {"a": 1, "b": 2}


def test_deep_merge_recursive():
    local = {"nested": {"x": 1, "y": 2}}
    remote = {"nested": {"y": 99, "z": 3}}
    result = deep_merge(local, remote)
    assert result == {"nested": {"x": 1, "y": 99, "z": 3}}


# ── Sync logic ────────────────────────────────────────────────────────────


@respx.mock
async def test_sync_writes_primary_data_to_store():
    store = MemoryObjectStore()
    col = _make_col()
    respx.get("https://primary.example.com/v1/pull/posts/featured").respond(
        200, json=_primary_response({"title": "Hello"}, hash_val="hash1")
    )

    async with httpx.AsyncClient() as client:
        manager = ReplicaManager(store, [col], client=client)
        await manager.sync_now("featured")

    raw = await store.get_string("posts/featured")
    assert raw is not None
    doc = json.loads(raw)
    assert doc["data"] == {"title": "Hello"}


@respx.mock
async def test_sync_skips_write_when_hash_unchanged():
    store = MemoryObjectStore()
    col = _make_col()

    # Pre-populate local store with same data
    await push(store, "posts/featured", {"title": "Hello"}, None)
    local_raw = await store.get_string("posts/featured")
    local_hash = json.loads(local_raw)["hash"]

    respx.get("https://primary.example.com/v1/pull/posts/featured").respond(
        200, json=_primary_response({"title": "Hello"}, hash_val=local_hash)
    )

    async with httpx.AsyncClient() as client:
        manager = ReplicaManager(store, [col], client=client)
        manager._last_hash["featured"] = local_hash  # simulate already synced
        call_count_before = len(respx.calls)
        await manager.sync_now("featured")

    # Store content should be unchanged
    raw = await store.get_string("posts/featured")
    assert json.loads(raw)["data"] == {"title": "Hello"}


@respx.mock
async def test_sync_empty_primary_is_noop():
    store = MemoryObjectStore()
    col = _make_col()
    respx.get("https://primary.example.com/v1/pull/posts/featured").respond(
        200, json={"data": {}, "hash": "", "timestamp": 1000}
    )

    async with httpx.AsyncClient() as client:
        manager = ReplicaManager(store, [col], client=client)
        await manager.sync_now("featured")

    assert await store.get_string("posts/featured") is None


@respx.mock
async def test_sync_bidirectional_merges_local_and_remote():
    store = MemoryObjectStore()
    col = _make_col(write_mode=WriteMode.BIDIRECTIONAL)

    # Local has {a: 1, b: 2}; primary has {b: 99, c: 3}
    await push(store, "posts/featured", {"a": 1, "b": 2}, None)

    respx.get("https://primary.example.com/v1/pull/posts/featured").respond(
        200, json=_primary_response({"b": 99, "c": 3}, hash_val="newhash")
    )

    async with httpx.AsyncClient() as client:
        manager = ReplicaManager(store, [col], client=client)
        await manager.sync_now("featured")

    raw = await store.get_string("posts/featured")
    doc = json.loads(raw)
    # remote wins on b; local a survives; remote adds c
    assert doc["data"]["a"] == 1
    assert doc["data"]["b"] == 99
    assert doc["data"]["c"] == 3


@respx.mock
async def test_on_notification_triggers_sync():
    store = MemoryObjectStore()
    col = _make_col(sync_triggers=[SyncTrigger.WEBHOOK])
    respx.get("https://primary.example.com/v1/pull/posts/featured").respond(
        200, json=_primary_response({"title": "From notification"}, hash_val="notifhash")
    )

    async with httpx.AsyncClient() as client:
        manager = ReplicaManager(store, [col], client=client)
        await manager.on_notification("featured")

    raw = await store.get_string("posts/featured")
    assert json.loads(raw)["data"] == {"title": "From notification"}


@respx.mock
async def test_on_pull_triggers_sync():
    store = MemoryObjectStore()
    col = _make_col(sync_triggers=[SyncTrigger.ON_PULL])
    respx.get("https://primary.example.com/v1/pull/posts/featured").respond(
        200, json=_primary_response({"title": "Fresh"}, hash_val="freshhash")
    )

    async with httpx.AsyncClient() as client:
        manager = ReplicaManager(store, [col], client=client)
        await manager.on_pull("featured")

    raw = await store.get_string("posts/featured")
    assert json.loads(raw)["data"] == {"title": "Fresh"}


@respx.mock
async def test_primary_error_calls_on_error_handler():
    """Background sync paths (on_notification, on_pull) catch primary errors via on_error
    rather than propagating them to the caller."""
    store = MemoryObjectStore()
    col = _make_col(sync_triggers=[SyncTrigger.WEBHOOK])
    respx.get("https://primary.example.com/v1/pull/posts/featured").respond(503)

    errors: list[tuple[str, Exception]] = []

    async with httpx.AsyncClient() as client:
        manager = ReplicaManager(store, [col], client=client, on_error=lambda name, exc: errors.append((name, exc)))
        await manager.on_notification("featured")  # should not raise

    assert len(errors) == 1
    assert errors[0][0] == "featured"


async def test_sync_now_unknown_collection_raises():
    store = MemoryObjectStore()
    manager = ReplicaManager(store, [])
    with pytest.raises(ValueError, match="Unknown remote collection"):
        await manager.sync_now("nonexistent")


# ── on_pull cooldown ──────────────────────────────────────────────────────


@respx.mock
async def test_on_pull_respects_cooldown():
    """Second on_pull within cooldown window skips the primary."""
    store = MemoryObjectStore()
    col = _make_col(
        sync_triggers=[SyncTrigger.ON_PULL],
        on_pull_min_interval_ms=5_000,  # 5-second cooldown
    )
    route = respx.get("https://primary.example.com/v1/pull/posts/featured").respond(
        200, json=_primary_response({"title": "Hello"}, hash_val="hash1")
    )

    async with httpx.AsyncClient() as client:
        manager = ReplicaManager(store, [col], client=client)
        await manager.on_pull("featured")   # first call — hits primary
        await manager.on_pull("featured")   # within cooldown — should NOT hit primary

    assert route.call_count == 1


@respx.mock
async def test_on_pull_syncs_after_cooldown_expires():
    """on_pull syncs again once the cooldown has elapsed."""
    store = MemoryObjectStore()
    col = _make_col(
        sync_triggers=[SyncTrigger.ON_PULL],
        on_pull_min_interval_ms=1,  # 1 ms — expires almost immediately
    )
    route = respx.get("https://primary.example.com/v1/pull/posts/featured").respond(
        200, json=_primary_response({"title": "Hello"}, hash_val="hash1")
    )

    async with httpx.AsyncClient() as client:
        manager = ReplicaManager(store, [col], client=client)
        await manager.on_pull("featured")   # first sync
        # Force last_sync_at into the past so the cooldown is expired
        manager._last_sync_at["featured"] = time.monotonic() - 1.0
        await manager.on_pull("featured")   # cooldown elapsed — hits primary again

    assert route.call_count == 2


@respx.mock
async def test_on_pull_no_cooldown_always_syncs():
    """Without on_pull_min_interval_ms, every on_pull hits the primary."""
    store = MemoryObjectStore()
    col = _make_col(sync_triggers=[SyncTrigger.ON_PULL])  # no cooldown
    route = respx.get("https://primary.example.com/v1/pull/posts/featured").respond(
        200, json=_primary_response({"title": "Hello"}, hash_val="hash1")
    )

    async with httpx.AsyncClient() as client:
        manager = ReplicaManager(store, [col], client=client)
        await manager.on_pull("featured")
        await manager.on_pull("featured")

    assert route.call_count == 2


# ── PUSH_ONLY write mode ─────────────────────────────────────────────────


@respx.mock
async def test_push_only_skips_sync_from_primary():
    """PUSH_ONLY collections never pull from the primary."""
    store = MemoryObjectStore()
    col = _make_col(write_mode=WriteMode.PUSH_ONLY)
    route = respx.get("https://primary.example.com/v1/pull/posts/featured").respond(
        200, json=_primary_response({"title": "Should not arrive"}, hash_val="x")
    )

    async with httpx.AsyncClient() as client:
        manager = ReplicaManager(store, [col], client=client)
        await manager.sync_now("featured")

    # Primary should never have been contacted
    assert route.call_count == 0
    # Store should remain empty — no data pulled
    assert await store.get_string("posts/featured") is None


@respx.mock
async def test_push_only_allows_local_writes():
    """PUSH_ONLY collections accept local writes to the store."""
    store = MemoryObjectStore()
    col = _make_col(write_mode=WriteMode.PUSH_ONLY)

    # Simulate a local push (as the route handler would do)
    from starfish_server.protocol.types import PushSuccess
    result = await push(store, "posts/featured", {"submitted": True}, None)
    assert isinstance(result, PushSuccess)

    raw = await store.get_string("posts/featured")
    assert json.loads(raw)["data"] == {"submitted": True}
