"""Tests for EncryptedObjectStore — ported from encrypted-store.test.ts."""

import pytest

from starfish_server.encryption.encrypted_store import EncryptedObjectStore
from tests.helpers import MemoryObjectStore


@pytest.mark.asyncio
async def test_round_trips_get_string_returns_original_after_put():
    inner = MemoryObjectStore()
    store = EncryptedObjectStore(inner, "server-secret", "user-id")

    await store.put("test/key", '{"hello":"world"}')
    result = await store.get_string("test/key")
    assert result == '{"hello":"world"}'


@pytest.mark.asyncio
async def test_data_is_encrypted_at_rest():
    inner = MemoryObjectStore()
    store = EncryptedObjectStore(inner, "server-secret", "user-id")

    plaintext = '{"secret":"data","balance":1000}'
    await store.put("test/key", plaintext)

    raw = await inner.get_string("test/key")
    assert raw is not None
    assert raw != plaintext
    assert "secret" not in raw
    assert "balance" not in raw


@pytest.mark.asyncio
async def test_different_salts_produce_different_ciphertexts():
    inner = MemoryObjectStore()
    store1 = EncryptedObjectStore(inner, "secret", "user-1")
    store2 = EncryptedObjectStore(inner, "secret", "user-2")

    await store1.put("key1", "same-data")
    await store2.put("key2", "same-data")

    raw1 = await inner.get_string("key1")
    raw2 = await inner.get_string("key2")
    assert raw1 != raw2


@pytest.mark.asyncio
async def test_wrong_key_raises_value_error():
    inner = MemoryObjectStore()
    store1 = EncryptedObjectStore(inner, "secret", "user-1")
    store2 = EncryptedObjectStore(inner, "secret", "user-2")

    await store1.put("test/key", "sensitive")
    with pytest.raises(ValueError, match="Decryption failed"):
        await store2.get_string("test/key")


@pytest.mark.asyncio
async def test_invalid_tag_is_wrapped_not_propagated():
    inner = MemoryObjectStore()
    store = EncryptedObjectStore(inner, "secret", "user")

    # Manually store corrupted ciphertext (valid base64, but garbage)
    import base64
    corrupted = base64.b64encode(b"\x00" * 12 + b"\xff" * 32).decode()
    await inner.put("key", corrupted)

    with pytest.raises(ValueError):
        await store.get_string("key")


@pytest.mark.asyncio
async def test_get_string_returns_none_for_missing_keys():
    inner = MemoryObjectStore()
    store = EncryptedObjectStore(inner, "secret", "user")

    assert await store.get_string("missing") is None


@pytest.mark.asyncio
async def test_list_delegates_to_inner_store():
    inner = MemoryObjectStore()
    store = EncryptedObjectStore(inner, "secret", "user")

    await store.put("prefix/a", "data-a")
    await store.put("prefix/b", "data-b")
    await store.put("other/c", "data-c")

    keys = await store.list_keys("prefix/")
    assert len(keys) == 2
    assert "prefix/a" in keys
    assert "prefix/b" in keys


@pytest.mark.asyncio
async def test_delete_and_delete_many_delegate_to_inner_store():
    inner = MemoryObjectStore()
    store = EncryptedObjectStore(inner, "secret", "user")

    await store.put("a", "1")
    await store.put("b", "2")
    await store.put("c", "3")

    await store.delete("a")
    assert await inner.get_string("a") is None

    await store.delete_many(["b", "c"])
    assert await inner.get_string("b") is None
    assert await inner.get_string("c") is None
