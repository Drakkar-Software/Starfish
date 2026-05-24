"""SyncManager.abort() must cancel an in-flight push or pull and leave
_last_hash / _local_data unchanged.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock

from starfish_sdk.client import StarfishClient
from starfish_sdk.sync import SyncManager, AbortError
from starfish_protocol.types import PullResult, PushSuccess


def _make_slow_push_client() -> tuple[StarfishClient, "asyncio.Future"]:
    """Client whose push() waits until the returned future resolves."""
    future: asyncio.Future = asyncio.get_event_loop().create_future()

    async def slow_push(*args, **kwargs):  # type: ignore[override]
        return await asyncio.shield(future)

    client = StarfishClient.__new__(StarfishClient)
    client.push = AsyncMock(side_effect=slow_push)  # type: ignore
    client.pull = AsyncMock(return_value=PullResult(data={}, hash="initial-hash", timestamp=100))  # type: ignore
    return client, future


def _make_slow_pull_client() -> tuple[StarfishClient, "asyncio.Future"]:
    """Client whose pull() waits until the returned future resolves."""
    future: asyncio.Future = asyncio.get_event_loop().create_future()

    async def slow_pull(*args, **kwargs):  # type: ignore[override]
        return await asyncio.shield(future)

    client = StarfishClient.__new__(StarfishClient)
    client.pull = AsyncMock(side_effect=slow_pull)  # type: ignore
    client.push = AsyncMock()  # type: ignore
    return client, future


# ─── abort during push ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_abort_rejects_inflight_push_with_abort_error():
    """Abort during a pending push must raise AbortError, not succeed."""
    client, future = _make_slow_push_client()
    sync = SyncManager(client=client, pull_path="/pull/x", push_path="/push/x")
    sync.set_hash("initial-hash")

    push_task = asyncio.ensure_future(sync.push({"x": 1}))
    await asyncio.sleep(0)  # let push reach the await

    sync.abort()
    future.set_result(PushSuccess(hash="new-hash", timestamp=200))

    with pytest.raises(AbortError):
        await push_task


@pytest.mark.asyncio
async def test_abort_does_not_update_hash_or_data():
    """State must be unchanged when push is aborted mid-flight."""
    client, future = _make_slow_push_client()
    sync = SyncManager(client=client, pull_path="/pull/x", push_path="/push/x")
    sync.set_hash("initial-hash")

    push_task = asyncio.ensure_future(sync.push({"x": 1}))
    await asyncio.sleep(0)

    sync.abort()
    future.set_result(PushSuccess(hash="new-hash", timestamp=200))

    try:
        await push_task
    except AbortError:
        pass

    assert sync.hash == "initial-hash"
    assert sync.data == {}


def test_is_aborted_getter():
    """is_aborted getter must reflect abort state."""
    client = StarfishClient.__new__(StarfishClient)
    sync = SyncManager(client=client, pull_path="/pull/x", push_path="/push/x")

    assert sync.is_aborted is False
    sync.abort()
    assert sync.is_aborted is True


@pytest.mark.asyncio
async def test_push_on_pre_aborted_manager_rejects_immediately():
    """Pre-aborted manager must raise AbortError without calling client.push."""
    client = StarfishClient.__new__(StarfishClient)
    client.push = AsyncMock()  # type: ignore
    client.pull = AsyncMock()  # type: ignore
    sync = SyncManager(client=client, pull_path="/pull/x", push_path="/push/x")

    sync.abort()
    with pytest.raises(AbortError):
        await sync.push({"x": 1})

    client.push.assert_not_called()


# ─── abort during pull ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_abort_rejects_inflight_pull_with_abort_error():
    """Abort during a pending pull must raise AbortError and leave hash unchanged."""
    client, future = _make_slow_pull_client()
    sync = SyncManager(client=client, pull_path="/pull/x", push_path="/push/x")

    pull_task = asyncio.ensure_future(sync.pull())
    await asyncio.sleep(0)

    sync.abort()
    future.set_result(PullResult(data={"k": 1}, hash="pulled-hash", timestamp=500))

    with pytest.raises(AbortError):
        await pull_task

    assert sync.hash is None
