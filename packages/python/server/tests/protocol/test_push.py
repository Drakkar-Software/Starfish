"""Tests for push operation — ported from push.test.ts."""

import asyncio
import json

import pytest

from starfish_server.protocol.push import push
from starfish_server.protocol.types import PushSuccess, PushConflict, StoredDocument
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
    await push(store, "col/doc1", {"a": 1}, None)

    r2 = await push(store, "col/doc1", {"a": 2}, "wrong-hash")
    assert isinstance(r2, PushConflict)
    assert r2.error == "hash_mismatch"


@pytest.mark.asyncio
async def test_second_push_with_null_base_hash_fails():
    store = MemoryObjectStore()
    await push(store, "col/doc1", {"a": 1}, None)

    r2 = await push(store, "col/doc1", {"a": 2}, None)
    assert isinstance(r2, PushConflict)


@pytest.mark.asyncio
async def test_stores_correct_document_format():
    store = MemoryObjectStore()
    await push(store, "col/doc1", {"b": 2, "a": 1}, None)

    raw = await store.get_string("col/doc1")
    assert raw is not None
    doc = json.loads(raw)
    assert doc["v"] == 1
    assert doc["data"] == {"b": 2, "a": 1}
    assert len(doc["hash"]) == 64
    assert isinstance(doc["timestamps"]["a"], int)
    assert isinstance(doc["timestamps"]["b"], int)


@pytest.mark.asyncio
async def test_skip_timestamps_stores_empty_timestamps():
    store = MemoryObjectStore()
    result = await push(store, "col/doc1", {"_encrypted": "blob"}, None, skip_timestamps=True)
    assert isinstance(result, PushSuccess)

    raw = await store.get_string("col/doc1")
    doc = json.loads(raw)
    assert doc["timestamps"] == {}


@pytest.mark.asyncio
async def test_skip_timestamps_works_on_subsequent_pushes():
    store = MemoryObjectStore()
    r1 = await push(store, "col/doc1", {"_encrypted": "v1"}, None, skip_timestamps=True)
    assert isinstance(r1, PushSuccess)

    r2 = await push(store, "col/doc1", {"_encrypted": "v2"}, r1.hash, skip_timestamps=True)
    assert isinstance(r2, PushSuccess)

    raw = await store.get_string("col/doc1")
    doc = json.loads(raw)
    assert doc["timestamps"] == {}
    assert doc["data"] == {"_encrypted": "v2"}


@pytest.mark.asyncio
async def test_preserves_timestamps_for_unchanged_values():
    store = MemoryObjectStore()
    r1 = await push(store, "col/doc1", {"a": 1, "b": 2}, None)
    assert isinstance(r1, PushSuccess)

    raw1 = await store.get_string("col/doc1")
    doc1 = json.loads(raw1)
    ts_a = doc1["timestamps"]["a"]

    await asyncio.sleep(0.001)
    await push(store, "col/doc1", {"a": 1, "b": 3}, r1.hash)

    raw2 = await store.get_string("col/doc1")
    doc2 = json.loads(raw2)
    assert doc2["timestamps"]["a"] == ts_a
    assert doc2["timestamps"]["b"] != ts_a


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
    import json
    raw = json.loads(await store.get_string("col/doc"))
    assert raw["hash"] == sentinel


@pytest.mark.asyncio
async def test_precomputed_timestamps_are_stored():
    store = MemoryObjectStore()
    pre_ts = {"items": [1714000001, 1714000002]}
    await push(store, "col/doc", {"items": [{"a": 1}, {"a": 2}]}, None, precomputed_timestamps=pre_ts)
    import json
    raw = json.loads(await store.get_string("col/doc"))
    assert raw["timestamps"] == pre_ts
