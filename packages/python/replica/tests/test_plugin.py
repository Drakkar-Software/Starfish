"""Tests for create_replica_server_plugin — route hooks, validation, shutdown."""


import asyncio

import httpx
import pytest
import respx

from starfish_protocol.plugins import PullHookContext, PushHookContext
from starfish_server.config.schema import CollectionConfig, SyncConfig

from starfish_replica.config import RemoteConfig, SyncTrigger, WriteMode
from starfish_replica.plugin import create_replica_server_plugin
from tests.helpers import MemoryObjectStore


def _col(**kwargs) -> CollectionConfig:
    defaults = dict(
        name="featured",
        storagePath="posts/featured",
        readRoles=["public"],
        writeRoles=[],
        encryption="none",
        maxBodyBytes=65536,
    )
    defaults.update(kwargs)
    return CollectionConfig(**defaults)


def _config() -> SyncConfig:
    return SyncConfig(version=1, collections=[_col()])


def _remote(**kwargs) -> RemoteConfig:
    defaults = dict(url="https://primary.example.com/v1", pullPath="/pull/posts/featured")
    defaults.update(kwargs)
    return RemoteConfig(**defaults)


def test_invalid_config_raises_at_construction():
    with pytest.raises(ValueError, match="invalid configuration"):
        create_replica_server_plugin(
            store=MemoryObjectStore(),
            sync_config=_config(),
            collections={"featured": _remote(writeMode=WriteMode.PUSH_THROUGH)},  # missing push_path
        )


async def test_before_pull_rejects_push_only():
    replica = create_replica_server_plugin(
        store=MemoryObjectStore(),
        sync_config=_config(),
        collections={"featured": _remote(writeMode=WriteMode.PUSH_ONLY)},
    )
    res = await replica.plugin.before_pull(PullHookContext(collection="featured", params={}))
    assert res.action == "reject"
    assert res.status == 405
    assert "write-only" in res.error


async def test_before_pull_proceeds_for_non_remote():
    replica = create_replica_server_plugin(
        store=MemoryObjectStore(),
        sync_config=_config(),
        collections={"featured": _remote()},
    )
    res = await replica.plugin.before_pull(PullHookContext(collection="other", params={}))
    assert res.action == "proceed"


@respx.mock
async def test_before_pull_syncs_on_pull_trigger():
    route = respx.get("https://primary.example.com/v1/pull/posts/featured").respond(
        200, json={"data": {"a": 1}, "hash": "h1", "timestamp": 1}
    )
    replica = create_replica_server_plugin(
        store=MemoryObjectStore(),
        sync_config=_config(),
        collections={"featured": _remote(syncTriggers=[SyncTrigger.ON_PULL])},
    )
    res = await replica.plugin.before_pull(PullHookContext(collection="featured", params={}))
    assert res.action == "proceed"
    assert route.call_count == 1
    await replica.manager.stop()


async def test_intercept_push_rejects_pull_only():
    replica = create_replica_server_plugin(
        store=MemoryObjectStore(),
        sync_config=_config(),
        collections={"featured": _remote(writeMode=WriteMode.PULL_ONLY)},
    )
    res = await replica.plugin.intercept_push(
        PushHookContext(collection="featured", params={}, raw_body="{}")
    )
    assert res.action == "reject"
    assert res.status == 405
    assert "read-only" in res.error


@respx.mock
async def test_intercept_push_proxies_push_through():
    respx.post("https://primary.example.com/v1/push/posts/featured").respond(
        200, json={"hash": "primary-hash", "timestamp": 5}
    )
    respx.get("https://primary.example.com/v1/pull/posts/featured").respond(
        200, json={"data": {}, "hash": "primary-hash", "timestamp": 5}
    )
    replica = create_replica_server_plugin(
        store=MemoryObjectStore(),
        sync_config=_config(),
        collections={
            "featured": _remote(writeMode=WriteMode.PUSH_THROUGH, pushPath="/push/posts/featured")
        },
    )
    res = await replica.plugin.intercept_push(
        PushHookContext(collection="featured", params={}, raw_body='{"data": {}}')
    )
    assert res.action == "respond"
    assert res.status == 200
    assert res.body == {"hash": "primary-hash", "timestamp": 5}
    await asyncio.sleep(0)  # let the background sync task run under respx
    await replica.manager.stop()


async def test_intercept_push_proceeds_for_bidirectional():
    replica = create_replica_server_plugin(
        store=MemoryObjectStore(),
        sync_config=_config(),
        collections={
            "featured": _remote(writeMode=WriteMode.BIDIRECTIONAL, pushPath="/push/posts/featured")
        },
    )
    res = await replica.plugin.intercept_push(
        PushHookContext(collection="featured", params={}, raw_body="{}")
    )
    assert res.action == "proceed"
    await replica.manager.stop()


async def test_shutdown_stops_manager():
    replica = create_replica_server_plugin(
        store=MemoryObjectStore(),
        sync_config=_config(),
        collections={"featured": _remote(syncTriggers=[SyncTrigger.SCHEDULED])},
    )
    await replica.manager.start()
    assert len(replica.manager._tasks) == 1
    await replica.plugin.shutdown()
    assert replica.manager._tasks == []
