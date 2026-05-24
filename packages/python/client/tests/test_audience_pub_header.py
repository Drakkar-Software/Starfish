"""Tests that StarfishClient emits X-Starfish-Pub for audience redemption.

Mirror of TS ``tests/audience-pub-header.test.ts``.
"""

import base64
from unittest.mock import AsyncMock, MagicMock

import pytest

from starfish_sdk.client import StarfishClient

# The client only base64-encodes the cap for the header; it does not verify it.
_FAKE_CAP = {
    "v": 1,
    "kind": "audience",
    "iss": "aa" * 32,
    "issUserId": "x",
    "scope": {"ops": ["read"], "collections": ["c"]},
    "nbf": 0,
    "exp": 0,
    "nonce": base64.b64encode(bytes(16)).decode("ascii"),
}


class _Provider:
    def __init__(self, pub_hex: str | None) -> None:
        self._pub_hex = pub_hex

    async def get_cap(self) -> dict:
        ctx = {"cap": _FAKE_CAP, "dev_ed_priv_hex": "11" * 32}
        if self._pub_hex is not None:
            ctx["pub_hex"] = self._pub_hex
        return ctx


def _ok_response() -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.text = ""
    resp.json.return_value = {"data": {}, "hash": "", "timestamp": 0}
    return resp


@pytest.mark.asyncio
async def test_emits_pub_header_when_provider_returns_pub_hex() -> None:
    mock_http = AsyncMock()
    mock_http.get.return_value = _ok_response()
    client = StarfishClient("http://test", client=mock_http, cap_provider=_Provider("bb" * 32))

    await client.pull("/pull/c/x")

    headers = mock_http.get.call_args.kwargs["headers"]
    assert headers["X-Starfish-Pub"] == "bb" * 32
    assert headers["Authorization"].startswith("Cap ")


@pytest.mark.asyncio
async def test_omits_pub_header_for_device_member() -> None:
    mock_http = AsyncMock()
    mock_http.get.return_value = _ok_response()
    client = StarfishClient("http://test", client=mock_http, cap_provider=_Provider(None))

    await client.pull("/pull/c/x")

    headers = mock_http.get.call_args.kwargs["headers"]
    assert "X-Starfish-Pub" not in headers
    assert isinstance(headers["X-Starfish-Sig"], str)
