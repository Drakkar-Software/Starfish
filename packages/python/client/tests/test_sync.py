"""Tests for SyncManager."""


from typing import Any
from unittest.mock import AsyncMock

import pytest

from starfish_sdk.client import StarfishClient
from starfish_sdk.sync import SyncManager
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
        "/push/test", {"newKey": "newValue"}, None, None
    )


def test_sync_manager_rejects_partial_encryption_config():
    client = mock_client()
    with pytest.raises(ValueError, match="encryption"):
        SyncManager(client, "/pull/test", "/push/test", encryption_secret="secret")


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
