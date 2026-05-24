"""v3.0 cap-cert request signing — wire-format tests for ``StarfishClient``.

When a ``cap_provider`` is set, every authenticated request must carry::

    Authorization: Cap <base64(stable_stringify(cap))>
    X-Starfish-Sig:    base64 Ed25519 signature
    X-Starfish-Ts:     unix ms (decimal string)
    X-Starfish-Nonce:  base64 nonce

The signature must validate against the cap's subject pubkey when replayed
through :func:`verify_request_signature`.
"""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from starfish_protocol.hash import stable_stringify
from starfish_protocol.request_signing import (
    RequestSignature,
    verify_request_signature,
)
from starfish_identities.cap_mint import mint_device_cap, scopes
from starfish_sdk.client import StarfishClient
from starfish_identities.identity import derive_root_identity


def _make_resp(status: int = 200, data: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = ""
    resp.headers = {}
    if data is not None:
        resp.json.return_value = data
    return resp


def _make_laptop_cap() -> tuple[dict, str, str]:
    alice = derive_root_identity("alice-root-passphrase")
    laptop = derive_root_identity("alice-laptop")
    cap = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": laptop.keys.ed_pub, "kemPubHex": laptop.keys.kem_pub},
        scopes.root_all(),
    )
    return cap, laptop.keys.ed_priv, laptop.keys.ed_pub


def _decode_cap_auth(authorization: str) -> dict:
    prefix = "Cap "
    assert authorization.startswith(prefix)
    return json.loads(base64.b64decode(authorization[len(prefix):]).decode("utf-8"))


@pytest.mark.asyncio
async def test_push_attaches_cap_headers():
    cap, dev_ed_priv, dev_ed_pub = _make_laptop_cap()

    async def get_cap():
        return {"cap": cap, "dev_ed_priv_hex": dev_ed_priv}

    cap_provider = MagicMock()
    cap_provider.get_cap = get_cap

    mock_http = AsyncMock()
    mock_http.post.return_value = _make_resp(200, {"hash": "h", "timestamp": 1})

    client = StarfishClient("http://test", client=mock_http, cap_provider=cap_provider)
    await client.push("/push/test", {"foo": "bar"}, None)

    headers = mock_http.post.call_args.kwargs["headers"]
    assert headers["Authorization"].startswith("Cap ")
    assert headers["X-Starfish-Sig"]
    assert headers["X-Starfish-Ts"].isdigit()
    assert headers["X-Starfish-Nonce"]

    parsed_cap = _decode_cap_auth(headers["Authorization"])
    assert parsed_cap["sub"] == dev_ed_pub

    body = mock_http.post.call_args.kwargs["content"]
    sig = RequestSignature(
        sig=headers["X-Starfish-Sig"],
        ts=int(headers["X-Starfish-Ts"]),
        nonce=headers["X-Starfish-Nonce"],
    )
    ok = verify_request_signature(
        "POST",
        "/push/test",
        body.encode("utf-8") if isinstance(body, str) else body,
        sig,
        dev_ed_pub,
        host="test",
    )
    assert ok is True


@pytest.mark.asyncio
async def test_pull_attaches_cap_headers_with_query():
    cap, dev_ed_priv, dev_ed_pub = _make_laptop_cap()

    async def get_cap():
        return {"cap": cap, "dev_ed_priv_hex": dev_ed_priv}

    cap_provider = MagicMock()
    cap_provider.get_cap = get_cap

    mock_http = AsyncMock()
    mock_http.get.return_value = _make_resp(200, {"data": {}, "hash": "h", "timestamp": 1})

    client = StarfishClient("http://test", client=mock_http, cap_provider=cap_provider)
    await client.pull("/pull/test", checkpoint=42)

    headers = mock_http.get.call_args.kwargs["headers"]
    assert headers["Authorization"].startswith("Cap ")
    # When using cap-cert auth, the client must serialize the query inline so the
    # signed `pathAndQuery` matches the URL the server sees.
    sig = RequestSignature(
        sig=headers["X-Starfish-Sig"],
        ts=int(headers["X-Starfish-Ts"]),
        nonce=headers["X-Starfish-Nonce"],
    )
    ok = verify_request_signature(
        "GET", "/pull/test?checkpoint=42", b"", sig, dev_ed_pub, host="test"
    )
    assert ok is True


@pytest.mark.asyncio
async def test_pull_attaches_cap_headers_without_query():
    cap, dev_ed_priv, dev_ed_pub = _make_laptop_cap()

    async def get_cap():
        return {"cap": cap, "dev_ed_priv_hex": dev_ed_priv}

    cap_provider = MagicMock()
    cap_provider.get_cap = get_cap

    mock_http = AsyncMock()
    mock_http.get.return_value = _make_resp(200, {"data": {}, "hash": "h", "timestamp": 1})

    client = StarfishClient("http://test", client=mock_http, cap_provider=cap_provider)
    await client.pull("/pull/test")

    headers = mock_http.get.call_args.kwargs["headers"]
    sig = RequestSignature(
        sig=headers["X-Starfish-Sig"],
        ts=int(headers["X-Starfish-Ts"]),
        nonce=headers["X-Starfish-Nonce"],
    )
    ok = verify_request_signature("GET", "/pull/test", b"", sig, dev_ed_pub, host="test")
    assert ok is True


@pytest.mark.asyncio
async def test_cap_auth_encodes_stable_stringify_b64():
    cap, dev_ed_priv, _ = _make_laptop_cap()

    async def get_cap():
        return {"cap": cap, "dev_ed_priv_hex": dev_ed_priv}

    cap_provider = MagicMock()
    cap_provider.get_cap = get_cap

    mock_http = AsyncMock()
    mock_http.get.return_value = _make_resp(200, {"data": {}, "hash": "h", "timestamp": 1})
    client = StarfishClient("http://test", client=mock_http, cap_provider=cap_provider)
    await client.pull("/pull/test")

    headers = mock_http.get.call_args.kwargs["headers"]
    expected = base64.b64encode(stable_stringify(cap).encode("utf-8")).decode("ascii")
    assert headers["Authorization"] == f"Cap {expected}"


@pytest.mark.asyncio
async def test_no_cap_headers_when_no_provider():
    mock_http = AsyncMock()
    mock_http.get.return_value = _make_resp(200, {"data": {}, "hash": "h", "timestamp": 1})
    client = StarfishClient("http://test", client=mock_http)
    await client.pull("/pull/test")

    headers = mock_http.get.call_args.kwargs["headers"]
    assert "Authorization" not in headers
    assert "X-Starfish-Sig" not in headers
    assert "X-Starfish-Ts" not in headers
    assert "X-Starfish-Nonce" not in headers
