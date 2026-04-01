"""Tests for SuiObjectStore using mocked JSON-RPC responses."""

import base64
import json

import httpx
import pytest
import respx

from starfish_server.storage.sui import SuiObjectStore, SuiStorageOptions, _MAX_OBJECT_BYTES


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FAKE_RPC = "https://sui-rpc.test"
FAKE_PACKAGE = "0xpkg"
FAKE_STORE = "0xstore"


@pytest.fixture
def opts():
    return SuiStorageOptions(
        rpc_url=FAKE_RPC,
        package_id=FAKE_PACKAGE,
        store_object_id=FAKE_STORE,
    )


@pytest.fixture
def opts_rw():
    """Options with a keypair (read-write mode)."""
    return SuiStorageOptions(
        rpc_url=FAKE_RPC,
        package_id=FAKE_PACKAGE,
        store_object_id=FAKE_STORE,
        keypair_b64=base64.b64encode(b"x" * 32).decode(),
    )


@pytest.fixture
async def store(opts):
    s = SuiObjectStore(opts)
    yield s
    await s.close()


@pytest.fixture
async def store_rw(opts_rw):
    s = SuiObjectStore(opts_rw)
    yield s
    await s.close()


# ---------------------------------------------------------------------------
# Helpers – mock RPC responses
# ---------------------------------------------------------------------------


def _dynamic_field_response(data_bytes: bytes, content_type: str = "application/json"):
    """Build a mock ``suix_getDynamicFieldObject`` response."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "data": {
                "content": {
                    "dataType": "moveObject",
                    "fields": {
                        "value": {
                            "fields": {
                                "data": list(data_bytes),
                                "content_type": content_type,
                            }
                        }
                    },
                }
            }
        },
    }


def _dynamic_field_not_found():
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "error": {
                "code": "dynamicFieldNotFound",
            }
        },
    }


def _dynamic_fields_page(names: list[str], has_next: bool = False, cursor: str | None = None):
    """Build a mock ``suix_getDynamicFields`` response page."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "data": [
                {"name": {"type": "0x1::string::String", "value": n}} for n in names
            ],
            "hasNextPage": has_next,
            "nextCursor": cursor,
        },
    }


# ---------------------------------------------------------------------------
# Read operations (get_string)
# ---------------------------------------------------------------------------


@respx.mock
async def test_get_string_found(store):
    data = b'{"hello": "world"}'
    respx.post(FAKE_RPC).mock(
        return_value=httpx.Response(200, json=_dynamic_field_response(data))
    )
    result = await store.get_string("docs/hello")
    assert result == '{"hello": "world"}'


@respx.mock
async def test_get_string_missing(store):
    respx.post(FAKE_RPC).mock(
        return_value=httpx.Response(200, json=_dynamic_field_not_found())
    )
    result = await store.get_string("missing/key")
    assert result is None


@respx.mock
async def test_get_string_base64_encoding(store):
    """The RPC may return data as a base64 string instead of a list."""
    raw = b"some text"
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "data": {
                "content": {
                    "dataType": "moveObject",
                    "fields": {
                        "value": {
                            "fields": {
                                "data": base64.b64encode(raw).decode(),
                                "content_type": "text/plain",
                            }
                        }
                    },
                }
            }
        },
    }
    respx.post(FAKE_RPC).mock(return_value=httpx.Response(200, json=body))
    result = await store.get_string("key")
    assert result == "some text"


# ---------------------------------------------------------------------------
# Read operations (get_bytes)
# ---------------------------------------------------------------------------


@respx.mock
async def test_get_bytes_found(store):
    data = b"\x89PNG"
    respx.post(FAKE_RPC).mock(
        return_value=httpx.Response(
            200, json=_dynamic_field_response(data, "image/png")
        )
    )
    result = await store.get_bytes("img/logo")
    assert result is not None
    body, ct = result
    assert body == b"\x89PNG"
    assert ct == "image/png"


@respx.mock
async def test_get_bytes_missing(store):
    respx.post(FAKE_RPC).mock(
        return_value=httpx.Response(200, json=_dynamic_field_not_found())
    )
    assert await store.get_bytes("missing") is None


# ---------------------------------------------------------------------------
# list_keys
# ---------------------------------------------------------------------------


@respx.mock
async def test_list_keys_basic(store):
    respx.post(FAKE_RPC).mock(
        return_value=httpx.Response(
            200, json=_dynamic_fields_page(["posts/a", "posts/b", "settings/x"])
        )
    )
    result = await store.list_keys("posts")
    assert result == ["posts/a", "posts/b"]


@respx.mock
async def test_list_keys_start_after(store):
    respx.post(FAKE_RPC).mock(
        return_value=httpx.Response(
            200, json=_dynamic_fields_page(["posts/a", "posts/b", "posts/c"])
        )
    )
    result = await store.list_keys("posts", start_after="posts/a")
    assert result == ["posts/b", "posts/c"]


@respx.mock
async def test_list_keys_limit(store):
    respx.post(FAKE_RPC).mock(
        return_value=httpx.Response(
            200, json=_dynamic_fields_page(["posts/a", "posts/b", "posts/c"])
        )
    )
    result = await store.list_keys("posts", limit=2)
    assert result == ["posts/a", "posts/b"]


@respx.mock
async def test_list_keys_pagination(store):
    route = respx.post(FAKE_RPC)
    route.side_effect = [
        httpx.Response(
            200,
            json=_dynamic_fields_page(["posts/a", "posts/b"], has_next=True, cursor="cur1"),
        ),
        httpx.Response(
            200,
            json=_dynamic_fields_page(["posts/c"], has_next=False),
        ),
    ]
    result = await store.list_keys("posts")
    assert result == ["posts/a", "posts/b", "posts/c"]


@respx.mock
async def test_list_keys_empty(store):
    respx.post(FAKE_RPC).mock(
        return_value=httpx.Response(200, json=_dynamic_fields_page([]))
    )
    result = await store.list_keys("nothing")
    assert result == []


# ---------------------------------------------------------------------------
# Write guards (read-only mode)
# ---------------------------------------------------------------------------


async def test_put_raises_readonly(store):
    with pytest.raises(RuntimeError, match="read-only mode"):
        await store.put("key", "value")


async def test_put_bytes_raises_readonly(store):
    with pytest.raises(RuntimeError, match="read-only mode"):
        await store.put_bytes("key", b"data", content_type="image/png")


async def test_delete_raises_readonly(store):
    with pytest.raises(RuntimeError, match="read-only mode"):
        await store.delete("key")


async def test_delete_many_raises_readonly(store):
    with pytest.raises(RuntimeError, match="read-only mode"):
        await store.delete_many(["a", "b"])


# ---------------------------------------------------------------------------
# Size validation
# ---------------------------------------------------------------------------


async def test_put_rejects_oversized(store_rw):
    big_body = "x" * (_MAX_OBJECT_BYTES + 1)
    with pytest.raises(ValueError, match="exceeds the SUI dynamic field limit"):
        await store_rw.put("key", big_body)


async def test_put_bytes_rejects_oversized(store_rw):
    big_body = b"x" * (_MAX_OBJECT_BYTES + 1)
    with pytest.raises(ValueError, match="exceeds the SUI dynamic field limit"):
        await store_rw.put_bytes("key", big_body, content_type="application/octet-stream")


# ---------------------------------------------------------------------------
# delete_many with empty list is a no-op
# ---------------------------------------------------------------------------


async def test_delete_many_empty_is_noop(store):
    """delete_many with an empty list should not attempt a transaction."""
    await store.delete_many([])  # should not raise even in read-only mode


# ---------------------------------------------------------------------------
# RPC error handling
# ---------------------------------------------------------------------------


@respx.mock
async def test_rpc_error_returns_none_for_get(store):
    """An RPC-level error for a get should return None, not crash."""
    respx.post(FAKE_RPC).mock(
        return_value=httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32000, "message": "object not found"},
            },
        )
    )
    result = await store.get_string("bad/key")
    assert result is None
