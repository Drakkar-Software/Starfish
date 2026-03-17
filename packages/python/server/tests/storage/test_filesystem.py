"""Tests for FilesystemObjectStore."""


import os
import pytest

from starfish_server.storage.filesystem import FilesystemObjectStore, FilesystemStorageOptions


@pytest.fixture
def store(tmp_path):
    return FilesystemObjectStore(FilesystemStorageOptions(base_dir=str(tmp_path)))


async def test_get_missing_key(store):
    assert await store.get_string("missing/key") is None


async def test_put_and_get(store):
    await store.put("docs/hello", "world")
    assert await store.get_string("docs/hello") == "world"


async def test_put_overwrites(store):
    await store.put("docs/hello", "first")
    await store.put("docs/hello", "second")
    assert await store.get_string("docs/hello") == "second"


async def test_delete(store):
    await store.put("docs/hello", "world")
    await store.delete("docs/hello")
    assert await store.get_string("docs/hello") is None


async def test_delete_missing_is_noop(store):
    await store.delete("does/not/exist")  # should not raise


async def test_delete_many(store):
    await store.put("a/1", "x")
    await store.put("a/2", "y")
    await store.put("b/1", "z")
    await store.delete_many(["a/1", "a/2"])
    assert await store.get_string("a/1") is None
    assert await store.get_string("a/2") is None
    assert await store.get_string("b/1") == "z"


async def test_list_prefix(store):
    await store.put("posts/a", "1")
    await store.put("posts/b", "2")
    await store.put("settings/x", "3")
    result = await store.list_keys("posts")
    assert result == ["posts/a", "posts/b"]


async def test_list_start_after(store):
    await store.put("posts/a", "1")
    await store.put("posts/b", "2")
    await store.put("posts/c", "3")
    result = await store.list_keys("posts", start_after="posts/a")
    assert result == ["posts/b", "posts/c"]


async def test_list_limit(store):
    await store.put("posts/a", "1")
    await store.put("posts/b", "2")
    await store.put("posts/c", "3")
    result = await store.list_keys("posts", limit=2)
    assert result == ["posts/a", "posts/b"]


async def test_path_traversal_rejected(store):
    with pytest.raises(ValueError):
        await store.put("../outside", "bad")

    with pytest.raises(ValueError):
        await store.get_string("../../etc/passwd")


async def test_invalid_key_rejected(store):
    with pytest.raises(ValueError):
        await store.put("has spaces/key", "value")
