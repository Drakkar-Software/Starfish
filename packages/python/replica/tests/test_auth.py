"""Tests for ReplicaAuth — per-request signing + cap auto-refresh."""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from starfish_identities import bootstrap_root_identity, mint_device_cap, scopes
from starfish_protocol.request_signing import verify_request_signature, RequestSignature
from starfish_replica import ReplicaAuth

PASSPHRASE = "correct horse battery staple"


def _decode_cap_header(header: str) -> dict:
    assert header.startswith("Cap ")
    return json.loads(base64.b64decode(header[len("Cap "):]).decode("utf-8"))


async def test_signs_request_and_attaches_headers() -> None:
    """A request through ReplicaAuth carries a valid signature + cap header."""
    creds = bootstrap_root_identity(PASSPHRASE)
    auth = ReplicaAuth(credentials=creds)

    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["req"] = request
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, auth=auth) as client:
        await client.get("https://primary.example.com:8443/v1/ns/pull/posts/x?a=1")

    req = captured["req"]
    # Header presence
    assert "X-Starfish-Sig" in req.headers
    assert "X-Starfish-Ts" in req.headers
    assert "X-Starfish-Nonce" in req.headers
    assert req.headers["Authorization"].startswith("Cap ")

    # The cap header decodes to the bootstrapped cap-cert.
    cap = _decode_cap_header(req.headers["Authorization"])
    assert cap["sub"] == creds.device["edPub"]

    # The signature verifies against the signer's pubkey over the canonical
    # request bytes (path+query incl. port in host).
    sig = RequestSignature(
        sig=req.headers["X-Starfish-Sig"],
        ts=int(req.headers["X-Starfish-Ts"]),
        nonce=req.headers["X-Starfish-Nonce"],
    )
    ok = verify_request_signature(
        "GET",
        "/v1/ns/pull/posts/x?a=1",
        b"",
        sig,
        creds.device["edPub"],
        host="primary.example.com:8443",
    )
    assert ok


async def test_signs_post_body() -> None:
    """POST body bytes are folded into the signature."""
    creds = bootstrap_root_identity(PASSPHRASE)
    auth = ReplicaAuth(credentials=creds)

    captured: dict[str, httpx.Request] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["req"] = request
        return httpx.Response(200, json={"hash": "abc"})

    transport = httpx.MockTransport(handler)
    body = b'{"data":{"k":"v"}}'
    async with httpx.AsyncClient(transport=transport, auth=auth) as client:
        await client.post("https://primary.example.com/v1/ns/push/p", content=body)

    req = captured["req"]
    sig = RequestSignature(
        sig=req.headers["X-Starfish-Sig"],
        ts=int(req.headers["X-Starfish-Ts"]),
        nonce=req.headers["X-Starfish-Nonce"],
    )
    assert verify_request_signature(
        "POST", "/v1/ns/push/p", body, sig, creds.device["edPub"],
        host="primary.example.com",
    )
    # A tampered body must fail verification.
    assert not verify_request_signature(
        "POST", "/v1/ns/push/p", b"tampered", sig, creds.device["edPub"],
        host="primary.example.com",
    )


async def test_passphrase_bootstrap_exposes_user_id() -> None:
    auth = ReplicaAuth(passphrase=PASSPHRASE)
    creds = bootstrap_root_identity(PASSPHRASE)
    assert auth.user_id == creds.user_id


def test_requires_exactly_one_credential_source() -> None:
    with pytest.raises(ValueError):
        ReplicaAuth()
    with pytest.raises(ValueError):
        ReplicaAuth(passphrase=PASSPHRASE, credentials=bootstrap_root_identity(PASSPHRASE))


async def test_cap_auto_refreshes_near_expiry() -> None:
    """When the cached cap is within the refresh margin, a new cap is minted."""
    creds = bootstrap_root_identity(PASSPHRASE)
    # Mint a short-lived cap (10s TTL) so refresh triggers immediately.
    from starfish_identities import MintOpts

    short_cap = mint_device_cap(
        creds.device["edPriv"],
        creds.device["edPub"],
        {"edPubHex": creds.device["edPub"], "kemPubHex": creds.device["kemPub"]},
        scopes.root_all(),
        MintOpts(ttl_sec=10),
    )
    short_creds = type(creds)(
        root_ed_pub=creds.root_ed_pub,
        user_id=creds.user_id,
        device=creds.device,
        cap_cert=short_cap,
    )

    # Clock sits just before the short cap's expiry → inside the refresh margin.
    now = [int(short_cap["exp"]) - 5]
    auth = ReplicaAuth(
        credentials=short_creds,
        refresh_margin_sec=24 * 3600,  # margin >> 10s TTL → always refresh
        clock=lambda: now[0],
    )
    original_exp = auth._cap_exp

    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.headers["Authorization"])
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    # Advance the clock so the (newly minted) cap's exp is far in the future and
    # the request-signing timestamp check on the freshly minted cap is sane.
    async with httpx.AsyncClient(transport=transport, auth=auth) as client:
        await client.get("https://primary.example.com/v1/ns/pull/x")

    # A fresh cap was minted (its exp is later than the short cap's).
    assert auth._cap_exp > original_exp
    # And the request still carries a valid cap header.
    cap = _decode_cap_header(captured[0])
    assert cap["sub"] == creds.device["edPub"]


async def test_cap_not_refreshed_when_fresh() -> None:
    """A cap well outside the refresh margin is reused verbatim."""
    creds = bootstrap_root_identity(PASSPHRASE)  # default 30d TTL
    auth = ReplicaAuth(credentials=creds, refresh_margin_sec=3600)
    original_exp = auth._cap_exp

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, auth=auth) as client:
        await client.get("https://primary.example.com/v1/ns/pull/x")

    assert auth._cap_exp == original_exp
