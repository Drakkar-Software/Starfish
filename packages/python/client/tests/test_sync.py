"""Tests for SyncManager."""


import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from starfish_sdk.client import StarfishClient
from starfish_sdk.sync import SyncManager, DocAuthorError
from starfish_sdk.types import ConflictError
from starfish_protocol.append_author import sign_doc_author
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
    # No signer configured → author proof is None (4th arg).
    client.push.assert_called_once_with(  # type: ignore
        "/push/test", {"newKey": "newValue"}, None, None
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

    async def push(
        path: str, data: dict, base_hash: str | None, author: dict | None = None
    ) -> PushSuccess:
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
async def test_incremental_pull_uses_configured_resolver_not_deep_merge():
    # The pull path must route through the configured on_conflict resolver (it
    # previously hardcoded deep_merge). A union resolver preserves a local-only
    # item that a shorter incremental snapshot omits — deep_merge would drop it.
    calls: list[tuple[dict, dict]] = []

    def union_resolver(local: dict, remote: dict) -> dict:
        calls.append((local, remote))
        by_id = {it["id"]: it for it in local.get("items", [])}
        for it in remote.get("items", []):
            by_id[it["id"]] = it
        return {**local, **remote, "items": list(by_id.values())}

    client = mock_client(
        pull_responses=[
            PullResult(data={"items": [{"id": "a"}, {"id": "b"}]}, hash="h1", timestamp=100),
            PullResult(data={"items": [{"id": "a"}]}, hash="h2", timestamp=200),
        ]
    )
    sync = SyncManager(client, "/pull/test", "/push/test", on_conflict=union_resolver)

    await sync.pull()  # first pull (checkpoint 0) → wholesale, resolver NOT called
    assert calls == []
    result = await sync.pull()  # incremental → resolver invoked
    assert len(calls) == 1

    ids = sorted(it["id"] for it in sync.data["items"])
    assert ids == ["a", "b"]  # 'b' survived the union (deep_merge would have dropped it)
    # The returned PullResult mirrors the merged local data (parity with TS).
    assert sorted(it["id"] for it in result.data["items"]) == ["a", "b"]


# ── verify_author (opt-in document author verification) ───────────────────────
#
# Regression: SyncManager.pull accepted whatever data the server returned without
# checking the author signature it also returns, so a malicious server could forge
# authorship/content on none-mode collections. verify_author mirrors the TS option
# and AppendLogCursor.verify_author: opt-in, default OFF (unchanged behavior).

# A real Ed25519 keypair (same one used by test_append.py).
_DOC_PRIV = "1133557799bbddff1133557799bbddff1133557799bbddff1133557799bbddff"
_DOC_PUB = "062f2ba3c6a5590364b0864d539af151907d09ea0b741b0811e0d761a059bda4"


def _signed_pull(data: dict, *, sign_over: dict | None = None, ts: int = 100) -> PullResult:
    # Document key for "/pull/test" is "test" — must match what the writer signed.
    signed = sign_doc_author("test", data if sign_over is None else sign_over, _DOC_PUB, _DOC_PRIV)
    return PullResult(
        data=data,
        hash="h1",
        timestamp=ts,
        author_pubkey=signed["authorPubkey"],
        author_signature=signed["authorSignature"],
    )


@pytest.mark.asyncio
async def test_verify_author_accepts_correctly_signed_snapshot():
    client = mock_client(pull_responses=[_signed_pull({"key": "value"})])
    sync = SyncManager(client, "/pull/test", "/push/test", verify_author=True)
    result = await sync.pull()
    assert result.data == {"key": "value"}
    assert sync.data == {"key": "value"}
    assert sync.checkpoint == 100


@pytest.mark.asyncio
async def test_verify_author_rejects_forged_snapshot_and_mutates_no_state():
    # Server tampers with data but replays a signature made over the original.
    client = mock_client(
        pull_responses=[_signed_pull({"key": "tampered"}, sign_over={"key": "original"})]
    )
    sync = SyncManager(client, "/pull/test", "/push/test", verify_author=True)
    with pytest.raises(DocAuthorError):
        await sync.pull()
    assert sync.data == {}
    assert sync.checkpoint == 0


@pytest.mark.asyncio
async def test_verify_author_rejects_missing_author_fields():
    client = mock_client(pull_responses=[PullResult(data={"key": "v"}, hash="h1", timestamp=100)])
    sync = SyncManager(client, "/pull/test", "/push/test", verify_author=True)
    with pytest.raises(DocAuthorError):
        await sync.pull()


@pytest.mark.asyncio
async def test_verify_author_rejects_foreign_pinned_pubkey():
    client = mock_client(pull_responses=[_signed_pull({"key": "value"})])
    sync = SyncManager(
        client,
        "/pull/test",
        "/push/test",
        verify_author={"expected_author_pubkey": "aa" * 32},
    )
    with pytest.raises(DocAuthorError):
        await sync.pull()


@pytest.mark.asyncio
async def test_verify_author_accepts_matching_pinned_pubkey_case_insensitive():
    client = mock_client(pull_responses=[_signed_pull({"key": "value"})])
    sync = SyncManager(
        client,
        "/pull/test",
        "/push/test",
        verify_author={"expected_author_pubkey": _DOC_PUB.upper()},
    )
    result = await sync.pull()
    assert result.data == {"key": "value"}


@pytest.mark.asyncio
async def test_verify_author_disabled_by_default_accepts_unsigned_snapshot():
    client = mock_client(pull_responses=[PullResult(data={"key": "value"}, hash="h1", timestamp=100)])
    sync = SyncManager(client, "/pull/test", "/push/test")  # default: verification off
    result = await sync.pull()
    assert result.data == {"key": "value"}


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
