"""Tests for MemoryObjectStore and CustomObjectStore."""

import pytest

from starfish_server.storage.memory import MemoryObjectStore, CustomObjectStore, _global_data


@pytest.fixture
def store():
    return MemoryObjectStore(data={})


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


async def test_list_empty_prefix(store):
    assert await store.list_keys("nothing") == []


async def test_global_store_shared_between_instances():
    """Two default instances share the same backing dict."""
    _global_data.clear()
    try:
        a = MemoryObjectStore()
        b = MemoryObjectStore()
        await a.put("shared/key", "hello")
        assert await b.get_string("shared/key") == "hello"
    finally:
        _global_data.clear()


async def test_isolated_store_independent_from_global():
    """An isolated store (data={}) does not see global data."""
    _global_data.clear()
    try:
        global_store = MemoryObjectStore()
        isolated = MemoryObjectStore(data={})
        await global_store.put("k", "global")
        assert await isolated.get_string("k") is None
    finally:
        _global_data.clear()


async def test_custom_on_get():
    store = CustomObjectStore(on_get=lambda key: f"computed:{key}")
    assert await store.get_string("any/key") == "computed:any/key"


async def test_custom_on_put():
    captured: list[tuple[str, str]] = []

    async def my_put(key: str, body: str) -> None:
        captured.append((key, body))

    store = CustomObjectStore(on_put=my_put)
    await store.put("k", "v")
    assert captured == [("k", "v")]


async def test_custom_on_list():
    store = CustomObjectStore(
        on_list=lambda prefix, start_after, limit: ["remote/a", "remote/b"],
    )
    assert await store.list_keys("anything") == ["remote/a", "remote/b"]


async def test_custom_on_delete():
    deleted: list[str] = []
    store = CustomObjectStore(on_delete=lambda key: deleted.append(key))
    await store.delete("k")
    assert deleted == ["k"]


async def test_custom_async_callback():
    async def async_get(key: str) -> str:
        return f"async:{key}"

    store = CustomObjectStore(on_get=async_get)
    assert await store.get_string("foo") == "async:foo"


async def test_custom_delete_many_delegates():
    deleted: list[str] = []
    store = CustomObjectStore(on_delete=lambda key: deleted.append(key))
    await store.delete_many(["a/1", "a/2"])
    assert deleted == ["a/1", "a/2"]


# ---------------------------------------------------------------------------
# Binary storage (get_bytes / put_bytes)
# ---------------------------------------------------------------------------

async def test_put_bytes_and_get_bytes(store):
    await store.put_bytes("img/logo", b"\x89PNG", content_type="image/png")
    result = await store.get_bytes("img/logo")
    assert result is not None
    body, ct = result
    assert body == b"\x89PNG"
    assert ct == "image/png"


async def test_get_bytes_missing_key(store):
    assert await store.get_bytes("missing/key") is None


async def test_put_bytes_overwrites(store):
    await store.put_bytes("img/logo", b"first", content_type="image/png")
    await store.put_bytes("img/logo", b"second", content_type="image/jpeg")
    result = await store.get_bytes("img/logo")
    assert result is not None
    body, ct = result
    assert body == b"second"
    assert ct == "image/jpeg"


async def test_delete_cleans_binary(store):
    await store.put_bytes("img/logo", b"data", content_type="image/png")
    await store.delete("img/logo")
    assert await store.get_bytes("img/logo") is None


async def test_delete_many_cleans_binary(store):
    await store.put_bytes("img/a", b"a", content_type="image/png")
    await store.put_bytes("img/b", b"b", content_type="image/png")
    await store.delete_many(["img/a", "img/b"])
    assert await store.get_bytes("img/a") is None
    assert await store.get_bytes("img/b") is None


async def test_custom_no_callbacks_returns_safe_defaults():
    """Omitted callbacks return None / [] / no-op without raising."""
    store = CustomObjectStore()
    assert await store.get_string("k") is None
    await store.put("k", "v")  # no-op
    assert await store.list_keys("k") == []
    await store.delete("k")  # no-op


# ---------------------------------------------------------------------------
# Compare-and-swap (get_with_etag / put_if_match)
# ---------------------------------------------------------------------------

async def test_get_with_etag_missing_key(store):
    assert await store.get_with_etag("missing") is None


async def test_get_with_etag_stable_and_content_derived(store):
    await store.put("k", "v0")
    v1, e1 = await store.get_with_etag("k")
    assert v1 == "v0"
    _, e2 = await store.get_with_etag("k")
    assert e2 == e1  # same content → same etag
    await store.put("k", "v1")
    _, e3 = await store.get_with_etag("k")
    assert e3 != e1  # changed content → changed etag


async def test_put_if_match_create_if_absent(store):
    created = await store.put_if_match("k", "v0", None)
    assert created is not None
    assert await store.get_string("k") == "v0"
    # A second create-if-absent must fail — the key now exists.
    again = await store.put_if_match("k", "v1", None)
    assert again is None
    assert await store.get_string("k") == "v0"


async def test_put_if_match_matches_and_rejects_stale(store):
    await store.put("k", "v0")
    _, etag = await store.get_with_etag("k")
    ok = await store.put_if_match("k", "v1", etag)
    assert ok is not None
    # The old etag is now stale — a second write with it must fail.
    stale = await store.put_if_match("k", "v2", etag)
    assert stale is None
    assert await store.get_string("k") == "v1"


async def test_put_if_match_prevents_lost_update_across_instances():
    """Two instances sharing one backing dict must not clobber each other."""
    data: dict[str, str] = {}
    a = MemoryObjectStore(data=data)
    b = MemoryObjectStore(data=data)
    await a.put("k", "v0")

    # Both read the same state before either writes.
    _, ea = await a.get_with_etag("k")
    _, eb = await b.get_with_etag("k")

    assert await a.put_if_match("k", "vA", ea) is not None  # first writer wins
    assert await b.put_if_match("k", "vB", eb) is None  # conflict detected, not clobbered

    # b re-reads and retries → its write now lands on top of vA.
    _, eb2 = await b.get_with_etag("k")
    assert await b.put_if_match("k", "vB", eb2) is not None
    assert await a.get_string("k") == "vB"
