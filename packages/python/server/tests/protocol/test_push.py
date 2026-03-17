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
