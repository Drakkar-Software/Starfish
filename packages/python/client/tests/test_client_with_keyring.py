"""Tests for the StarfishClient `with_keyring` pull option."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from starfish_sdk.client import StarfishClient


def make_response(status_code: int, data: dict | None = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if data is not None:
        resp.json.return_value = data
    return resp


@pytest.mark.asyncio
async def test_pull_without_with_keyring_omits_param():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(
        200, {"data": {"_encrypted": "ct"}, "hash": "h", "timestamp": 1}
    )
    client = StarfishClient("http://test", client=mock_http)

    await client.pull("/pull/notes/abc")

    call_kwargs = mock_http.get.call_args.kwargs
    assert "withKeyring" not in (call_kwargs.get("params") or {})


@pytest.mark.asyncio
async def test_pull_with_keyring_true_adds_param():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(
        200,
        {
            "data": {"_encrypted": "ct"},
            "hash": "h",
            "timestamp": 1,
            "keyring": {"data": {"v": 1, "currentEpoch": 1}, "hash": "kh", "timestamp": 1},
        },
    )
    client = StarfishClient("http://test", client=mock_http)

    result = await client.pull("/pull/notes/abc", with_keyring=True)

    call_kwargs = mock_http.get.call_args.kwargs
    assert call_kwargs["params"]["withKeyring"] == "1"
    # Pull returns a structured object; the keyring lives on .keyring as a
    # PullKeyringProjection dataclass.
    assert result.keyring is not None
    assert result.keyring.data["v"] == 1
    assert result.keyring.hash == "kh"
    assert result.keyring.timestamp == 1


@pytest.mark.asyncio
async def test_pull_with_keyring_false_omits_param():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(
        200, {"data": {}, "hash": "", "timestamp": 0}
    )
    client = StarfishClient("http://test", client=mock_http)

    await client.pull("/pull/notes/abc", with_keyring=False)

    call_kwargs = mock_http.get.call_args.kwargs
    assert "withKeyring" not in (call_kwargs.get("params") or {})


@pytest.mark.asyncio
async def test_pull_with_keyring_composes_with_checkpoint():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(
        200, {"data": {}, "hash": "", "timestamp": 0}
    )
    client = StarfishClient("http://test", client=mock_http)

    await client.pull("/pull/notes/abc", checkpoint=100, with_keyring=True)

    call_kwargs = mock_http.get.call_args.kwargs
    params = call_kwargs["params"]
    assert params["checkpoint"] == "100"
    assert params["withKeyring"] == "1"


@pytest.mark.asyncio
async def test_pull_with_keyring_null_response():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(
        200,
        {"data": {"_encrypted": "ct"}, "hash": "h", "timestamp": 1, "keyring": None},
    )
    client = StarfishClient("http://test", client=mock_http)

    result = await client.pull("/pull/notes/abc", with_keyring=True)

    assert result.keyring is None
