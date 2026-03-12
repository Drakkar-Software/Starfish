"""Integration tests for SyncManager with encryption and signing."""


from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from starfish_sdk.client import StarfishClient
from starfish_sdk.crypto import Encryptor
from starfish_sdk.sync import SyncManager
from starfish_protocol.types import PullResult, PushSuccess
from starfish_sdk.types import ConflictError


def make_mock_client(
    pull_responses: list[PullResult] | None = None,
    push_responses: list[PushSuccess] | None = None,
) -> StarfishClient:
    client = MagicMock(spec=StarfishClient)
    client.pull = AsyncMock(side_effect=pull_responses or [])
    client.push = AsyncMock(side_effect=push_responses or [])
    return client


@pytest.mark.asyncio
async def test_encrypt_push_pull_round_trip():
    enc = Encryptor("secret", "user-salt")
    original_data = {"name": "alice", "score": 42}
    encrypted = enc.encrypt(original_data)

    client = make_mock_client(
        pull_responses=[PullResult(data=encrypted, hash="h1", timestamp=100)],
        push_responses=[PushSuccess(hash="h2", timestamp=200)],
    )
    sync = SyncManager(
        client, "/pull/test", "/push/test",
        encryption_secret="secret", encryption_salt="user-salt",
    )

    result = await sync.pull()
    assert result.data == original_data
    assert sync.data == original_data


@pytest.mark.asyncio
async def test_push_sends_signature():
    async def sign(data_str: str) -> str:
        return "test-signature"

    client = make_mock_client(
        push_responses=[PushSuccess(hash="h1", timestamp=100)],
    )
    sync = SyncManager(client, "/pull/test", "/push/test", sign_data=sign)
    sync._last_hash = "base"  # type: ignore[attr-defined]

    await sync.push({"key": "value"})

    assert client.push.call_args.args[3] == "test-signature"


@pytest.mark.asyncio
async def test_conflict_retry_resolves():
    call_count = 0

    async def push_side_effect(path, data, base_hash, sig=None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConflictError()
        return PushSuccess(hash="h2", timestamp=200)

    async def pull_side_effect(path, checkpoint=None):
        return PullResult(data={"remote": True}, hash="new-hash", timestamp=150)

    client = MagicMock(spec=StarfishClient)
    client.push = AsyncMock(side_effect=push_side_effect)
    client.pull = AsyncMock(side_effect=pull_side_effect)

    sync = SyncManager(client, "/pull/test", "/push/test", max_retries=3)
    sync._last_hash = "old-hash"  # type: ignore[attr-defined]

    with patch("starfish_sdk.sync.asyncio.sleep"):
        result = await sync.push({"local": True})

    assert result["hash"] == "h2"
    assert call_count == 2


@pytest.mark.asyncio
async def test_encrypted_conflict_retry_decrypts_remote():
    enc = Encryptor("secret", "user-salt")
    remote_data = {"remote": True}
    encrypted_remote = enc.encrypt(remote_data)

    call_count = 0

    async def push_side_effect(path, data, base_hash, sig=None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConflictError()
        return PushSuccess(hash="h2", timestamp=200)

    async def pull_side_effect(path, checkpoint=None):
        return PullResult(data=encrypted_remote, hash="new-hash", timestamp=150)

    client = MagicMock(spec=StarfishClient)
    client.push = AsyncMock(side_effect=push_side_effect)
    client.pull = AsyncMock(side_effect=pull_side_effect)

    sync = SyncManager(
        client, "/pull/test", "/push/test",
        encryption_secret="secret", encryption_salt="user-salt",
    )
    sync._last_hash = "old-hash"  # type: ignore[attr-defined]

    with patch("starfish_sdk.sync.asyncio.sleep"):
        await sync.push({"local": True})

    assert call_count == 2
