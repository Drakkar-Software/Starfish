"""Tests for SyncManager."""


from typing import Any
from unittest.mock import AsyncMock

import pytest

from starfish_protocol.hash import stable_stringify
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
async def test_sign_data_signs_encrypted_payload():
    """Regression: sign_data must sign the encrypted payload, not the plaintext.

    When both encryption and signing are active, the server verifies the
    signature against the ciphertext wrapper it receives.  The SDK must
    therefore sign stable_stringify(encrypted_payload).
    """
    signed_strings: list[str] = []

    async def capture_signer(data: str) -> str:
        signed_strings.append(data)
        return "dummy-sig"

    secret = "a]cZ#8=6gT{>w$Q}"
    salt = "user-public-key-abc123"
    info = "starfish-e2e"
    plaintext = {"hello": "world", "nested": {"a": 1}}

    client = mock_client()
    manager = SyncManager(
        client=client,
        pull_path="/pull/test",
        push_path="/push/test",
        encryption_secret=secret,
        encryption_salt=salt,
        encryption_info=info,
        sign_data=capture_signer,
    )

    await manager.push(plaintext)

    # Verify signer was called exactly once
    assert len(signed_strings) == 1

    # The push call's second arg is the actual payload sent to the server
    actual_payload = client.push.call_args[0][1]  # type: ignore

    # The signed string must be stable_stringify of the encrypted payload
    assert signed_strings[0] == stable_stringify(actual_payload)

    # And it must NOT be the plaintext stringification
    assert signed_strings[0] != stable_stringify(plaintext)

    # The payload must be an encrypted wrapper (has _encrypted key)
    assert "_encrypted" in actual_payload


@pytest.mark.asyncio
async def test_sign_data_signs_plaintext_when_no_encryption():
    """When no encryptor is configured, sign_data signs the raw data dict."""
    signed_strings: list[str] = []

    async def capture_signer(data: str) -> str:
        signed_strings.append(data)
        return "dummy-sig"

    plaintext = {"key": "value"}
    client = mock_client()
    manager = SyncManager(
        client=client,
        pull_path="/pull/test",
        push_path="/push/test",
        sign_data=capture_signer,
    )

    await manager.push(plaintext)

    assert len(signed_strings) == 1
    # Without encryption, payload == pending_data, so signed string matches plaintext
    assert signed_strings[0] == stable_stringify(plaintext)


@pytest.mark.asyncio
async def test_push_sends_signature_to_server():
    """The signature returned by sign_data must be forwarded to client.push()."""
    async def fake_signer(data: str) -> str:
        return "test-signature-abc"

    client = mock_client()
    manager = SyncManager(
        client=client,
        pull_path="/pull/test",
        push_path="/push/test",
        sign_data=fake_signer,
    )

    await manager.push({"foo": "bar"})

    # Fourth positional arg to client.push is the signature
    assert client.push.call_args[0][3] == "test-signature-abc"  # type: ignore


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
