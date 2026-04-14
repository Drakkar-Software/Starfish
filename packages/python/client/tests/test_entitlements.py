"""Tests for pull_entitlements client helper."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from starfish_sdk.entitlements import pull_entitlements
from starfish_sdk.client import StarfishClient
from starfish_sdk.types import StarfishHttpError


def _make_pull_result(data: dict) -> MagicMock:
    result = MagicMock()
    result.data = data
    result.hash = "abc"
    result.timestamp = 1000
    return result


def _make_client(pull_result=None, pull_error=None) -> StarfishClient:
    client = MagicMock(spec=StarfishClient)
    if pull_error is not None:
        client.pull = AsyncMock(side_effect=pull_error)
    else:
        client.pull = AsyncMock(return_value=pull_result)
    return client


@pytest.mark.asyncio
async def test_returns_features_list():
    client = _make_client(_make_pull_result({"features": ["premium-package-1", "paid-cloud-sync"]}))

    features = await pull_entitlements(client, "alice")
    assert sorted(features) == ["paid-cloud-sync", "premium-package-1"]


@pytest.mark.asyncio
async def test_returns_empty_when_field_absent():
    client = _make_client(_make_pull_result({}))

    features = await pull_entitlements(client, "alice")
    assert features == []


@pytest.mark.asyncio
async def test_returns_empty_when_field_not_a_list():
    client = _make_client(_make_pull_result({"features": "not-a-list"}))

    features = await pull_entitlements(client, "alice")
    assert features == []


@pytest.mark.asyncio
async def test_returns_empty_when_data_is_none():
    result = MagicMock()
    result.data = None
    result.hash = None
    result.timestamp = 0
    client = _make_client(result)

    features = await pull_entitlements(client, "alice")
    assert features == []


@pytest.mark.asyncio
async def test_filters_non_string_elements():
    client = _make_client(_make_pull_result({"features": ["valid", 42, None, True, "also-valid"]}))

    features = await pull_entitlements(client, "alice")
    assert sorted(features) == ["also-valid", "valid"]


@pytest.mark.asyncio
async def test_calls_pull_with_correct_default_path():
    client = _make_client(_make_pull_result({"features": []}))

    await pull_entitlements(client, "abc123")

    client.pull.assert_called_once_with("/pull/users/abc123/entitlements")


@pytest.mark.asyncio
async def test_respects_custom_path_template():
    client = _make_client(_make_pull_result({"features": ["pro"]}))

    features = await pull_entitlements(client, "alice", path="/pull/ents/{user_id}")

    client.pull.assert_called_once_with("/pull/ents/alice")
    assert features == ["pro"]


@pytest.mark.asyncio
async def test_respects_custom_field():
    client = _make_client(_make_pull_result({"slugs": ["pro"]}))

    features = await pull_entitlements(client, "alice", field="slugs")
    assert features == ["pro"]


@pytest.mark.asyncio
async def test_returns_empty_on_404():
    client = _make_client(pull_error=StarfishHttpError(404, "Not Found"))

    features = await pull_entitlements(client, "alice")
    assert features == []


@pytest.mark.asyncio
async def test_reraises_non_404_http_errors():
    client = _make_client(pull_error=StarfishHttpError(500, "Internal Server Error"))

    with pytest.raises(StarfishHttpError) as exc_info:
        await pull_entitlements(client, "alice")
    assert exc_info.value.status == 500


@pytest.mark.asyncio
async def test_reraises_non_http_errors():
    client = _make_client(pull_error=Exception("network failure"))

    with pytest.raises(Exception, match="network failure"):
        await pull_entitlements(client, "alice")
