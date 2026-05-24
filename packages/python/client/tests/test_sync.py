"""Tests for SyncManager."""


import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from starfish_sdk.client import StarfishClient
from starfish_sdk.sync import SyncManager
from starfish_sdk.types import ConflictError
from starfish_protocol.types import PullResult, PushSuccess


def mock_client(
    pull_responses: list[PullResult] | None = None,
    push_responses: list[PushSuccess] | None = None,
) -> StarfishClient:
    client = StarfishClient.__new__(StarfishClient)
    pull_data = pull_responses or [
        PullResult(data={"key": "value"}, hash="abc123", timestamp=1000)
    ]
    push_data = push_responses or [
        PushSuccess(hash="def456", timestamp=2000)
    ]
    client.pull = AsyncMock(side_effect=pull_data)  # type: ignore
    client.push = AsyncMock(side_effect=push_data)  # type: ignore
    return client


@pytest.mark.asyncio
async def test_pull_stores_state():
    client = mock_client()
    sync = SyncManager(client, "/pull/test", "/push/test")

    result = await sync.pull()
    assert result.data == {"key": "value"}
    assert sync.data == {"key": "value"}
    assert sync.hash == "abc123"
    assert sync.checkpoint == 1000


@pytest.mark.asyncio
async def test_push_sends_data():
    client = mock_client()
    sync = SyncManager(client, "/pull/test", "/push/test")

    result = await sync.push({"newKey": "newValue"})
    assert result["hash"] == "def456"
    assert result["timestamp"] == 2000
    assert sync.hash == "def456"
    client.push.assert_called_once_with(  # type: ignore
        "/push/test", {"newKey": "newValue"}, None
    )


@pytest.mark.asyncio
async def test_incremental_pull_merges():
    client = mock_client(
        pull_responses=[
            PullResult(data={"a": 1, "b": 2}, hash="h1", timestamp=100),
            PullResult(data={"b": 3}, hash="h2", timestamp=200),
        ]
    )
    sync = SyncManager(client, "/pull/test", "/push/test")

    await sync.pull()  # full pull
    assert sync.data == {"a": 1, "b": 2}

    await sync.pull()  # incremental — merges
    assert sync.data == {"a": 1, "b": 3}


@pytest.mark.asyncio
async def test_incremental_pull_replaces_array_wholesale_and_keeps_local_only_keys():
    # deep_merge is not element-wise: a remote list replaces the local one (not
    # concatenated), while a local-only key survives. Pins the merge contract
    # through the client's incremental path. Mirrors sync.test.ts.
    client = mock_client(
        pull_responses=[
            PullResult(data={"items": [1, 2, 3], "k": "v"}, hash="h1", timestamp=100),
            PullResult(data={"items": [9]}, hash="h2", timestamp=200),
        ]
    )
    sync = SyncManager(client, "/pull/test", "/push/test")

    await sync.pull()
    assert sync.data == {"items": [1, 2, 3], "k": "v"}
    await sync.pull()  # incremental merge
    assert sync.data == {"items": [9], "k": "v"}


def _stateful_client(initial_hash: str, initial_data: dict) -> tuple[StarfishClient, dict]:
    """A faithful stateful 'server': a push succeeds only when its base_hash equals
    the current hash (push.py: ``base_hash != current_hash`` → ConflictError); the
    loser conflict-retries (pull → default deep_merge → retry). The ``asyncio.sleep(0)``
    models real network I/O yielding so two gathered pushes interleave the way httpx
    would — a synchronous mock would run them serially and hide the conflict path."""
    state = {"hash": initial_hash, "data": dict(initial_data)}

    async def push(path: str, data: dict, base_hash: str | None) -> PushSuccess:
        await asyncio.sleep(0)
        if base_hash != state["hash"]:
            raise ConflictError()
        state["data"] = data
        state["hash"] = "h-" + json.dumps(data, sort_keys=True)
        return PushSuccess(hash=state["hash"], timestamp=1)

    async def pull(path: str, *args, **kwargs) -> PullResult:
        await asyncio.sleep(0)
        return PullResult(data=dict(state["data"]), hash=state["hash"], timestamp=1)

    client = StarfishClient.__new__(StarfishClient)
    client.push = push  # type: ignore
    client.pull = pull  # type: ignore
    return client, state


@pytest.mark.asyncio
async def test_two_concurrent_pushes_both_land():
    # asyncio.gather of two pushes on the same manager: the loser conflict-retries
    # and the default deep_merge unions both writes — no lost update (TS parity).
    client, state = _stateful_client("h0", {})
    sync = SyncManager(client, "/pull/test", "/push/test")
    sync.set_hash("h0")  # both pushes start from the same base_hash
    await asyncio.gather(sync.push({"x": 1}), sync.push({"y": 2}))
    assert state["data"] == {"x": 1, "y": 2}


@pytest.mark.asyncio
async def test_stale_or_corrupt_hash_self_heals_via_conflict_retry():
    # A rehydrated truncated/garbage hash makes the first push conflict (it can't
    # match the real current hash); the retry loop pulls, merges, and re-pushes
    # against the real hash. The server treats any non-matching base_hash as a
    # conflict (not a 400), so recovery is automatic. TS parity.
    client, state = _stateful_client("real-hash", {"a": 1})
    sync = SyncManager(client, "/pull/test", "/push/test")
    sync.set_hash("truncated-garbage")
    result = await sync.push({"b": 2})
    assert state["data"] == {"a": 1, "b": 2}
    assert result["hash"] == state["hash"]


@pytest.mark.asyncio
async def test_conflict_resolver_error_propagates():
    # A resolver that rejects the merge (e.g. a validation failure) must surface its
    # error to the caller rather than be silently swallowed. Mirrors sync.test.ts.
    def _raising_resolver(local, remote):
        raise ValueError("merge rejected by validator")

    client = mock_client(
        pull_responses=[
            PullResult(data={"a": 1}, hash="h1", timestamp=100),  # initial pull
            PullResult(data={"a": 1, "remote": True}, hash="h2", timestamp=200),  # conflict re-pull
        ],
        push_responses=[ConflictError()],  # AsyncMock side_effect raises this on the push attempt
    )
    sync = SyncManager(client, "/pull/test", "/push/test", on_conflict=_raising_resolver)

    await sync.pull()
    with pytest.raises(ValueError, match="merge rejected by validator"):
        await sync.push({"a": 2})
