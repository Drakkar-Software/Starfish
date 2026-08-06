"""ReplicaManager's back-compat surface after the ChannelScheduler split.

test_manager.py is the real regression net (it passes unmodified). This file
covers the compatibility machinery that split introduced explicitly, rather
than relying on it being exercised incidentally:

- ``_last_hash`` used to be a plain ``dict[str, str]`` on the manager; it now
  lives per-channel on each HttpReplicaChannel (mirroring TS, where
  ``_lastHash`` is a per-channel scalar). ``_LastHashView`` maps the old
  mapping access onto the new location. test_manager.py:95 pokes it exactly
  once (``manager._last_hash["featured"] = local_hash``) — everything else
  about the view is untested without this file.
- ``remote_for`` / ``proxy_push`` must still 404-or-None on a non-HTTP channel,
  since a ChannelScheduler built from space channels has no RemoteConfig.
"""

from __future__ import annotations

import httpx
import pytest

from starfish_replica.channel import ChannelSchedule, ScheduledChannel
from starfish_replica.config import RemoteCollection, RemoteConfig, SyncTrigger, WriteMode
from starfish_replica.http_channel import HttpReplicaChannel
from starfish_replica.manager import ReplicaManager
from starfish_replica.scheduler import ChannelScheduler
from tests.helpers import MemoryObjectStore


def _make_col(name: str = "featured") -> RemoteCollection:
    return RemoteCollection(
        name=name,
        storage_path=f"posts/{name}",
        remote=RemoteConfig(
            url="https://primary.example.com/v1",
            pull_path=f"/pull/posts/{name}",
            push_path=f"/push/posts/{name}",
            interval_ms=60_000,
            write_mode=WriteMode.PULL_ONLY,
            sync_triggers=[SyncTrigger.SCHEDULED],
        ),
    )


# ── ReplicaManager is a ChannelScheduler ──────────────────────────────────────


def test_manager_is_a_channel_scheduler():
    manager = ReplicaManager(MemoryObjectStore(), [])
    assert isinstance(manager, ChannelScheduler)


def test_manager_builds_one_http_channel_per_collection():
    manager = ReplicaManager(MemoryObjectStore(), [_make_col("a"), _make_col("b")])
    channels = [e.channel for e in manager._entries]
    assert [c.name for c in channels] == ["a", "b"]
    assert all(isinstance(c, HttpReplicaChannel) for c in channels)


def test_manager_translates_remote_config_into_a_channel_schedule():
    col = _make_col()
    col.remote.interval_ms = 12_345
    col.remote.on_pull_min_interval_ms = 999
    col.remote.sync_triggers = [SyncTrigger.ON_PULL]

    manager = ReplicaManager(MemoryObjectStore(), [col])
    schedule = manager._entries[0].schedule

    assert schedule.interval_ms == 12_345
    assert schedule.on_pull_min_interval_ms == 999
    assert schedule.triggers == [SyncTrigger.ON_PULL]


def test_all_channels_share_the_managers_http_client():
    manager = ReplicaManager(MemoryObjectStore(), [_make_col("a"), _make_col("b")])
    clients = {id(e.channel._client) for e in manager._entries}
    assert len(clients) == 1
    assert next(iter(clients)) == id(manager._client)


# ── _last_hash back-compat view ───────────────────────────────────────────────


def test_last_hash_set_then_get_round_trips():
    manager = ReplicaManager(MemoryObjectStore(), [_make_col()])
    manager._last_hash["featured"] = "h1"
    assert manager._last_hash["featured"] == "h1"


def test_last_hash_writes_through_to_the_channel():
    manager = ReplicaManager(MemoryObjectStore(), [_make_col()])
    manager._last_hash["featured"] = "h1"
    assert manager._entries[0].channel._last_hash == "h1"


def test_last_hash_reads_through_from_the_channel():
    manager = ReplicaManager(MemoryObjectStore(), [_make_col()])
    manager._entries[0].channel._last_hash = "set-on-channel"
    assert manager._last_hash["featured"] == "set-on-channel"


def test_last_hash_unset_channel_raises_key_error():
    manager = ReplicaManager(MemoryObjectStore(), [_make_col()])
    with pytest.raises(KeyError):
        manager._last_hash["featured"]


def test_last_hash_unknown_name_raises_key_error():
    manager = ReplicaManager(MemoryObjectStore(), [_make_col()])
    with pytest.raises(KeyError):
        manager._last_hash["not-a-collection"]


def test_last_hash_delete_clears_the_channel_value():
    manager = ReplicaManager(MemoryObjectStore(), [_make_col()])
    manager._last_hash["featured"] = "h1"
    del manager._last_hash["featured"]
    assert manager._entries[0].channel._last_hash is None


def test_last_hash_iteration_and_len_only_count_set_channels():
    manager = ReplicaManager(MemoryObjectStore(), [_make_col("a"), _make_col("b")])
    assert len(manager._last_hash) == 0
    manager._last_hash["a"] = "h-a"
    assert list(manager._last_hash) == ["a"]
    assert len(manager._last_hash) == 1
    manager._last_hash["b"] = "h-b"
    assert sorted(manager._last_hash) == ["a", "b"]
    assert len(manager._last_hash) == 2


def test_last_hash_is_per_channel_not_shared():
    manager = ReplicaManager(MemoryObjectStore(), [_make_col("a"), _make_col("b")])
    manager._last_hash["a"] = "h-a"
    assert manager._entries[1].channel._last_hash is None


def test_last_hash_supports_the_get_idiom():
    # MutableMapping gives .get() for free, but only if __getitem__ raises
    # KeyError correctly rather than returning None.
    manager = ReplicaManager(MemoryObjectStore(), [_make_col()])
    assert manager._last_hash.get("featured") is None
    manager._last_hash["featured"] = "h1"
    assert manager._last_hash.get("featured") == "h1"


# ── remote_for / proxy_push on non-HTTP channels ──────────────────────────────


def test_remote_for_returns_the_channels_remote_config():
    col = _make_col()
    manager = ReplicaManager(MemoryObjectStore(), [col])
    assert manager.remote_for("featured") is col.remote


def test_remote_for_unknown_collection_returns_none():
    manager = ReplicaManager(MemoryObjectStore(), [_make_col()])
    assert manager.remote_for("nope") is None


class _FakeSpaceChannel:
    """Stands in for a non-HTTP channel (e.g. SpaceMirrorChannel)."""

    name = "mirror"

    async def sync(self, ctx) -> None:
        return None


def test_remote_for_returns_none_on_a_non_http_channel():
    manager = ReplicaManager(MemoryObjectStore(), [])
    manager._entries.append(
        ScheduledChannel(channel=_FakeSpaceChannel(), schedule=ChannelSchedule())
    )
    assert manager.remote_for("mirror") is None


async def test_proxy_push_404s_on_a_non_http_channel():
    manager = ReplicaManager(MemoryObjectStore(), [])
    manager._entries.append(
        ScheduledChannel(channel=_FakeSpaceChannel(), schedule=ChannelSchedule())
    )
    status, body = await manager.proxy_push("mirror", "{}")
    assert status == 404
    assert "Unknown remote collection" in body["error"]


async def test_proxy_push_404s_on_an_unknown_collection():
    manager = ReplicaManager(MemoryObjectStore(), [])
    status, _ = await manager.proxy_push("nope", "{}")
    assert status == 404


def test_last_hash_view_skips_non_http_channels():
    manager = ReplicaManager(MemoryObjectStore(), [_make_col()])
    manager._entries.append(
        ScheduledChannel(channel=_FakeSpaceChannel(), schedule=ChannelSchedule())
    )
    manager._last_hash["featured"] = "h1"
    # The space channel has no _last_hash and must not appear or blow up.
    assert list(manager._last_hash) == ["featured"]
    with pytest.raises(KeyError):
        manager._last_hash["mirror"]


# ── client ownership ──────────────────────────────────────────────────────────


async def test_stop_closes_an_owned_client():
    manager = ReplicaManager(MemoryObjectStore(), [_make_col()])  # no client passed → owned
    assert manager._owned_client is True
    await manager.stop()
    assert manager._client.is_closed


async def test_stop_leaves_an_injected_client_open():
    async with httpx.AsyncClient() as client:
        manager = ReplicaManager(MemoryObjectStore(), [_make_col()], client=client)
        assert manager._owned_client is False
        await manager.stop()
        assert not client.is_closed


# ── from_channels ─────────────────────────────────────────────────────────────


async def test_from_channels_builds_a_scheduler_over_non_http_channels():
    entry = ScheduledChannel(channel=_FakeSpaceChannel(), schedule=ChannelSchedule())
    scheduler = ReplicaManager.from_channels([entry])

    assert isinstance(scheduler, ChannelScheduler)
    await scheduler.sync_now("mirror")  # drives the channel without any HTTP setup


async def test_from_channels_forwards_the_on_error_handler():
    class Boom:
        name = "boom"

        async def sync(self, ctx):
            raise RuntimeError("x")

    errors: list[str] = []
    scheduler = ReplicaManager.from_channels(
        [ScheduledChannel(channel=Boom(), schedule=ChannelSchedule())],
        on_error=lambda n, e: errors.append(n),
    )
    await scheduler.sync_all()
    assert errors == ["boom"]
