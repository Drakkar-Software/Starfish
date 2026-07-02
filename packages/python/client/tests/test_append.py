"""Tests for append-only pull/push via StarfishClient."""

import pytest
import respx
import httpx

from starfish_sdk.client import StarfishClient
from starfish_sdk.types import StarfishHttpError
from starfish_protocol.types import PushSuccess, PullResult


BASE = "https://api.example.com/v1"
PUSH_SUCCESS = PushSuccess(hash="abc123", timestamp=1714000000)


def _json_resp(data: object) -> httpx.Response:
    return httpx.Response(200, json={"data": data, "hash": "h1", "timestamp": 0})


@pytest.mark.asyncio
async def test_push_null_base_hash_for_append():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.post("/v1/push/events").mock(return_value=httpx.Response(
            200, json={"hash": "abc123", "timestamp": 1714000000}
        ))
        async with StarfishClient(BASE) as client:
            result = await client.push("/push/events", {"type": "click"}, None)
    assert result == PUSH_SUCCESS


@pytest.mark.asyncio
async def test_pull_append_field_returns_list():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [{"msg": "a"}, {"msg": "b"}]}))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/events", append_field="items")
    assert result == [{"msg": "a"}, {"msg": "b"}]


@pytest.mark.asyncio
async def test_pull_since_defaults_field_to_items():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [{"n": 1}]}))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/events", since=1000)
    assert result == [{"n": 1}]


@pytest.mark.asyncio
async def test_pull_append_returns_empty_when_data_none():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp(None))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/events", append_field="items")
    assert result == []


@pytest.mark.asyncio
async def test_pull_append_returns_empty_when_field_absent():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({}))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/events", append_field="items")
    assert result == []


@pytest.mark.asyncio
async def test_pull_append_returns_empty_when_not_list():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": "not-a-list"}))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/events", append_field="items")
    assert result == []


@pytest.mark.asyncio
async def test_pull_append_custom_field():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"logs": [{"x": 1}]}))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/events", append_field="logs")
    assert result == [{"x": 1}]


@pytest.mark.asyncio
async def test_pull_since_sends_checkpoint_param():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": []}))
        async with StarfishClient(BASE) as client:
            await client.pull("/pull/events", since=1714000000)
        assert "checkpoint=1714000000" in str(mock.calls[0].request.url)


@pytest.mark.asyncio
async def test_pull_last_sends_last_param():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": []}))
        async with StarfishClient(BASE) as client:
            await client.pull("/pull/events", last=10)
        assert "last=10" in str(mock.calls[0].request.url)


@pytest.mark.asyncio
async def test_pull_since_and_last_combined():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": []}))
        async with StarfishClient(BASE) as client:
            await client.pull("/pull/events", since=5000, last=20)
        url = str(mock.calls[0].request.url)
        assert "checkpoint=5000" in url
        assert "last=20" in url


@pytest.mark.asyncio
async def test_pull_limit_sends_limit_param():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": []}))
        async with StarfishClient(BASE) as client:
            await client.pull("/pull/events", limit=5)
        assert "limit=5" in str(mock.calls[0].request.url)


@pytest.mark.asyncio
async def test_pull_full_sends_full_param():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": []}))
        async with StarfishClient(BASE) as client:
            await client.pull("/pull/events", append_field="items", full=True)
        assert "full=true" in str(mock.calls[0].request.url)


@pytest.mark.asyncio
@pytest.mark.parametrize("bound", [{"since": 1}, {"limit": 1}, {"last": 1}])
async def test_pull_full_with_bound_raises(bound):
    # The client raises before sending — no HTTP call is made, so no mock needed.
    async with StarfishClient(BASE) as client:
        with pytest.raises(ValueError, match="full cannot be combined"):
            await client.pull("/pull/events", append_field="items", full=True, **bound)


@pytest.mark.asyncio
async def test_pull_no_append_options_returns_pull_result():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/settings").mock(return_value=httpx.Response(
            200, json={"data": {"key": "value"}, "hash": "h1", "timestamp": 123}
        ))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/settings")
    assert isinstance(result, PullResult)
    assert result.data == {"key": "value"}


@pytest.mark.asyncio
async def test_pull_negative_since_raises():
    async with StarfishClient(BASE) as client:
        with pytest.raises(ValueError, match="since must be non-negative"):
            await client.pull("/pull/events", since=-1)


@pytest.mark.asyncio
async def test_pull_negative_last_raises():
    async with StarfishClient(BASE) as client:
        with pytest.raises(ValueError, match="last must be non-negative"):
            await client.pull("/pull/events", last=-1)


# --- client.append (appendOnly) ---

@pytest.mark.asyncio
async def test_append_posts_data_and_returns_push_success_no_ts():
    with respx.mock(base_url="https://api.example.com") as mock:
        route = mock.post("/v1/push/events").mock(return_value=httpx.Response(
            200, json={"hash": "abc123", "timestamp": 1714000000}
        ))
        async with StarfishClient(BASE) as client:
            result = await client.append("/push/events", {"type": "click"})
    import json as _json
    sent = _json.loads(route.calls[0].request.content)
    assert sent == {"data": {"type": "click"}}
    assert "ts" not in sent
    assert result == PUSH_SUCCESS


@pytest.mark.asyncio
async def test_append_includes_ts_when_provided():
    with respx.mock(base_url="https://api.example.com") as mock:
        route = mock.post("/v1/push/events").mock(return_value=httpx.Response(
            200, json={"hash": "abc123", "timestamp": 1714000000}
        ))
        async with StarfishClient(BASE) as client:
            await client.append("/push/events", {"type": "click"}, ts=1714000123)
    import json as _json
    sent = _json.loads(route.calls[0].request.content)
    assert sent == {"data": {"type": "click"}, "ts": 1714000123}


@pytest.mark.asyncio
async def test_append_raises_on_409_non_monotonic():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.post("/v1/push/events").mock(return_value=httpx.Response(
            409, json={"error": "non_monotonic_timestamp", "latest": 100}
        ))
        async with StarfishClient(BASE) as client:
            with pytest.raises(StarfishHttpError):
                await client.append("/push/events", {"n": 1}, ts=1)


@pytest.mark.asyncio
async def test_pull_returns_ts_data_envelopes_for_append_only():
    envelopes = [{"ts": 100, "data": {"msg": "a"}}, {"ts": 200, "data": {"msg": "b"}}]
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": envelopes}))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/events", append_field="items")
    assert result == envelopes


# A real Ed25519 keypair so the emitted signature actually verifies; the cap is a
# minimal stand-in (the client only base64-encodes it for the header).
_KP_PRIV = "1133557799bbddff1133557799bbddff1133557799bbddff1133557799bbddff"
_KP_PUB = "062f2ba3c6a5590364b0864d539af151907d09ea0b741b0811e0d761a059bda4"
_FAKE_CAP = {
    "v": 1,
    "kind": "audience",
    "iss": "aa" * 32,
    "issUserId": "x",
    "scope": {"ops": ["write"], "collections": ["c"]},
    "nbf": 0,
    "exp": 0,
    "nonce": "AAAAAAAAAAAAAAAAAAAAAA==",
}


class _AudienceCapProvider:
    async def get_cap(self) -> dict:
        return {"cap": _FAKE_CAP, "dev_ed_priv_hex": _KP_PRIV, "pub_hex": _KP_PUB}


@pytest.mark.asyncio
async def test_append_signs_element_for_server_verification():
    import json
    from starfish_protocol.append_author import verify_append_author

    data = {"msg": "hi"}
    with respx.mock(base_url="https://api.example.com") as mock:
        route = mock.post("/v1/push/events").mock(
            return_value=httpx.Response(200, json={"hash": "h", "timestamp": 1})
        )
        async with StarfishClient(BASE, cap_provider=_AudienceCapProvider()) as client:
            await client.append("/push/events", data)

    body = json.loads(route.calls[0].request.content)
    assert body["authorPubkey"] == _KP_PUB
    # The client derives document_key="events" from the push path "/push/events".
    assert verify_append_author("events", data, body["authorPubkey"], body["authorSignature"]) is True


@pytest.mark.asyncio
async def test_append_sends_no_author_fields_without_cap_provider():
    import json

    with respx.mock(base_url="https://api.example.com") as mock:
        route = mock.post("/v1/push/events").mock(
            return_value=httpx.Response(200, json={"hash": "h", "timestamp": 1})
        )
        async with StarfishClient(BASE) as client:
            await client.append("/push/events", {"msg": "hi"})

    body = json.loads(route.calls[0].request.content)
    assert "authorPubkey" not in body
    assert "authorSignature" not in body


# --- client.append_anonymous ---

@pytest.mark.asyncio
async def test_append_anonymous_signs_when_signer_given():
    import json
    from starfish_protocol.append_author import verify_append_author

    data = {"msg": "hi"}
    signer = {"edPubHex": _KP_PUB, "edPrivHex": _KP_PRIV}
    with respx.mock(base_url="https://api.example.com") as mock:
        route = mock.post("/v1/push/inbox/alice/2024-01").mock(
            return_value=httpx.Response(200, json={"hash": "h", "timestamp": 1})
        )
        async with StarfishClient(BASE) as client:
            await client.append_anonymous("/push/inbox/alice/2024-01", data, signer)

    request = route.calls[0].request
    body = json.loads(request.content)
    assert body["data"] == data
    assert body["authorPubkey"] == _KP_PUB
    # The server derives document_key="inbox/alice/2024-01" from the push path.
    assert verify_append_author(
        "inbox/alice/2024-01", data, body["authorPubkey"], body["authorSignature"]
    ) is True
    # Anonymous append carries no auth header.
    assert "authorization" not in {k.lower() for k in request.headers.keys()}


@pytest.mark.asyncio
async def test_append_anonymous_omits_author_without_signer():
    import json

    with respx.mock(base_url="https://api.example.com") as mock:
        route = mock.post("/v1/push/inbox/bob").mock(
            return_value=httpx.Response(200, json={"hash": "h", "timestamp": 1})
        )
        async with StarfishClient(BASE) as client:
            await client.append_anonymous("/push/inbox/bob", {"x": 1})

    body = json.loads(route.calls[0].request.content)
    assert body == {"data": {"x": 1}}
    assert "authorPubkey" not in body
    assert "authorSignature" not in body
