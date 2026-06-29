"""Tests for push operation — ported from push.test.ts."""

import json
import time

import pytest

from starfish_server.protocol.push import push
from starfish_server.protocol.types import PushSuccess, PushConflict
from tests.helpers import MemoryObjectStore


@pytest.mark.asyncio
async def test_first_push_with_base_hash_none_succeeds():
    store = MemoryObjectStore()
    result = await push(store, "col/doc1", {"a": 1}, None)
    assert isinstance(result, PushSuccess)
    assert len(result.hash) == 64
    assert isinstance(result.timestamp, int)


@pytest.mark.asyncio
async def test_first_push_with_non_null_base_hash_fails():
    store = MemoryObjectStore()
    result = await push(store, "col/doc1", {"a": 1}, "wrong-hash")
    assert isinstance(result, PushConflict)
    assert result.error == "hash_mismatch"
    # a45: conflict carries current_hash; doc is missing so current_hash is "" (same as pull).
    assert result.current_hash == ""


@pytest.mark.asyncio
async def test_second_push_with_correct_base_hash_succeeds():
    store = MemoryObjectStore()
    r1 = await push(store, "col/doc1", {"a": 1}, None)
    assert isinstance(r1, PushSuccess)

    r2 = await push(store, "col/doc1", {"a": 2}, r1.hash)
    assert isinstance(r2, PushSuccess)


@pytest.mark.asyncio
async def test_second_push_with_wrong_base_hash_fails():
    store = MemoryObjectStore()
    r1 = await push(store, "col/doc1", {"a": 1}, None)

    r2 = await push(store, "col/doc1", {"a": 2}, "wrong-hash")
    assert isinstance(r2, PushConflict)
    assert r2.error == "hash_mismatch"
    # a45: conflict carries the authoritative stored hash so clients can retry immediately.
    assert r2.current_hash == r1.hash, (
        f"current_hash must match the stored hash H1={r1.hash!r}, got {r2.current_hash!r}"
    )


@pytest.mark.asyncio
async def test_second_push_with_null_base_hash_fails():
    store = MemoryObjectStore()
    r1 = await push(store, "col/doc1", {"a": 1}, None)

    r2 = await push(store, "col/doc1", {"a": 2}, None)
    assert isinstance(r2, PushConflict)
    # a45: current_hash is the stored hash even when baseHash=None.
    assert r2.current_hash == r1.hash


@pytest.mark.asyncio
async def test_stores_single_doc_level_ts_and_no_timestamps_tree():
    store = MemoryObjectStore()
    before = time.time_ns() // 1_000_000
    await push(store, "col/doc1", {"b": 2, "a": 1}, None)

    raw = await store.get_string("col/doc1")
    assert raw is not None
    doc = json.loads(raw)
    assert doc["v"] == 1
    assert doc["data"] == {"b": 2, "a": 1}
    assert len(doc["hash"]) == 64
    # A single document-level write timestamp, not a per-field timestamps tree.
    assert isinstance(doc["ts"], int)
    assert doc["ts"] >= before
    assert "timestamps" not in doc


@pytest.mark.asyncio
async def test_skip_timestamps_is_inert_no_op():
    """`skip_timestamps` is retained for call-site compatibility but no longer
    affects storage — the doc carries only the doc-level `ts`."""
    store = MemoryObjectStore()
    result = await push(store, "col/doc1", {"_encrypted": "blob"}, None, skip_timestamps=True)
    assert isinstance(result, PushSuccess)

    raw = await store.get_string("col/doc1")
    doc = json.loads(raw)
    assert "timestamps" not in doc
    assert isinstance(doc["ts"], int)
    assert doc["data"] == {"_encrypted": "blob"}


@pytest.mark.asyncio
async def test_corrupt_stored_document_does_not_crash_push():
    """A corrupt stored document must be handled gracefully, not raise a 500."""
    store = MemoryObjectStore()
    # Inject a corrupt (non-JSON) value directly into the store
    await store.put("col/corrupt", "NOT_VALID_JSON", content_type="application/json")

    # Should not raise; must return a PushConflict or PushSuccess, not an exception
    result = await push(store, "col/corrupt", {"a": 1}, None)
    # Corrupt document → current_hash = "" → baseHash=None with raw truthy → conflict
    assert isinstance(result, PushConflict), f"Expected PushConflict, got {result!r}"


@pytest.mark.asyncio
async def test_corrupt_stored_document_overwritable_with_empty_base_hash():
    """A corrupt document can be overwritten when the client passes baseHash=''."""
    store = MemoryObjectStore()
    await store.put("col/corrupt", "NOT_VALID_JSON", content_type="application/json")

    # Pass baseHash="" to match the "" current_hash that results from parse failure
    result = await push(store, "col/corrupt", {"recovered": True}, "")
    assert isinstance(result, PushSuccess), f"Expected PushSuccess, got {result!r}"


@pytest.mark.asyncio
async def test_precomputed_hash_is_stored():
    store = MemoryObjectStore()
    sentinel = "a" * 64
    await push(store, "col/doc", {"a": 1}, None, precomputed_hash=sentinel)
    raw = json.loads(await store.get_string("col/doc"))
    assert raw["hash"] == sentinel
