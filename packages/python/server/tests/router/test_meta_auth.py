"""Tests for ``authenticate_meta_request`` — the bodyless meta-request
authenticator shared by SSE-proxy-style endpoints.

Mirrors the verify pipeline of the sync cap-cert resolver but with an empty body
and no ``scope.paths`` enforcement.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from starfish_identities import identities_server_plugin
from starfish_protocol.cap import sign_cap_cert
from starfish_protocol.request_signing import sign_request
from starfish_server.auth.nonce_cache import create_in_memory_nonce_cache
from starfish_server.auth.revocation_store import create_in_memory_revocation_store
from starfish_server.plugins import compose_plugin_validators
from starfish_server.router.cap_resolver import authenticate_meta_request
from starfish_sharing import sharing_server_plugin

_HOST = "test"
_PATH = "/v1/events?products=p1"
_PLUGIN_VALIDATORS = compose_plugin_validators(
    [identities_server_plugin, sharing_server_plugin]
)


@dataclass
class _Root:
    ed_priv_hex: str
    ed_pub_hex: str
    user_id: str
    kem_pub_hex: str


def _make_root(seed: int) -> _Root:
    priv = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    kem_pub = (
        X25519PrivateKey.from_private_bytes(bytes([seed + 1]) * 32)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    return _Root(
        ed_priv_hex=priv_bytes.hex(),
        ed_pub_hex=pub_bytes.hex(),
        user_id=hashlib.sha256(pub_bytes).hexdigest()[:32],
        kem_pub_hex=kem_pub.hex(),
    )


def _mint_device(iss: _Root, sub: _Root, *, nbf: int, ttl: int = 3600) -> dict:
    unsigned = {
        "v": 1,
        "kind": "device",
        "iss": iss.ed_pub_hex,
        "issUserId": iss.user_id,
        "sub": sub.ed_pub_hex,
        "subKem": sub.kem_pub_hex,
        "scope": {"ops": ["read", "list", "write"], "collections": ["notes"], "paths": ["notes/*"]},
        "nbf": nbf,
        "exp": nbf + ttl,
        "nonce": base64.b64encode(bytes([7]) * 16).decode("ascii"),
    }
    return sign_cap_cert(unsigned, iss.ed_priv_hex)


def _mint_member(
    iss: _Root,
    sub: _Root,
    *,
    nbf: int,
    ttl: int = 3600,
    collections: list[str] | None = None,
) -> dict:
    unsigned = {
        "v": 1,
        "kind": "member",
        "iss": iss.ed_pub_hex,
        "issUserId": iss.user_id,
        "sub": sub.ed_pub_hex,
        "subKem": sub.kem_pub_hex,
        "subUserId": sub.user_id,
        "scope": {
            "ops": ["read", "list"],
            "collections": collections or ["shared"],
            "paths": ["shared/{identity}/*"],
        },
        "nbf": nbf,
        "exp": nbf + ttl,
        "nonce": base64.b64encode(bytes([3]) * 16).decode("ascii"),
    }
    return sign_cap_cert(unsigned, iss.ed_priv_hex)


def _cap_header(cert: dict) -> str:
    return "Cap " + base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")


def _headers(cert: dict, signer_priv_hex: str, *, nonce_seed: int = 0) -> dict[str, str]:
    sig = sign_request("GET", _PATH, b"", signer_priv_hex, host=_HOST)
    return {
        "authorization": _cap_header(cert),
        "x-starfish-sig": sig.sig,
        "x-starfish-ts": str(sig.ts),
        "x-starfish-nonce": sig.nonce,
    }


async def _auth(
    headers: dict[str, str],
    *,
    nonce_cache=None,
    revocation_store=None,
    accept_kinds=("device", "member"),
) -> str | None:
    return await authenticate_meta_request(
        method="GET",
        path_and_query=_PATH,
        host=_HOST,
        headers=headers,
        nonce_cache=nonce_cache or create_in_memory_nonce_cache(),
        revocation_store=revocation_store or create_in_memory_revocation_store(),
        plugin_validators=_PLUGIN_VALIDATORS,
        accept_kinds=accept_kinds,
    )


@pytest.mark.asyncio
async def test_accepts_device_cap() -> None:
    root = _make_root(0x10)
    cert = _mint_device(root, root, nbf=int(time.time()) - 10)
    identity = await _auth(_headers(cert, root.ed_priv_hex))
    assert identity == root.user_id


@pytest.mark.asyncio
async def test_accepts_member_cap() -> None:
    alice = _make_root(0x20)
    bob = _make_root(0x22)
    cert = _mint_member(alice, bob, nbf=int(time.time()) - 10)
    identity = await _auth(_headers(cert, bob.ed_priv_hex))
    # member cap binds to the SUBJECT's userId.
    assert identity == bob.user_id


@pytest.mark.asyncio
async def test_rejects_audience_cap() -> None:
    # An audience cap is not in accept_kinds → reject up-front.
    alice = _make_root(0x30)
    bob = _make_root(0x32)
    nbf = int(time.time()) - 10
    unsigned = {
        "v": 1,
        "kind": "audience",
        "iss": alice.ed_pub_hex,
        "issUserId": alice.user_id,
        "sub": "",
        "scope": {"ops": ["read"], "collections": ["shared"], "paths": ["shared/x"]},
        "nbf": nbf,
        "exp": nbf + 3600,
        "nonce": base64.b64encode(bytes([9]) * 16).decode("ascii"),
    }
    cert = sign_cap_cert(unsigned, alice.ed_priv_hex)
    sig = sign_request("GET", _PATH, b"", bob.ed_priv_hex, host=_HOST)
    headers = {
        "authorization": _cap_header(cert),
        "x-starfish-sig": sig.sig,
        "x-starfish-ts": str(sig.ts),
        "x-starfish-nonce": sig.nonce,
        "x-starfish-pub": bob.ed_pub_hex,
    }
    assert await _auth(headers) is None


@pytest.mark.asyncio
async def test_rejects_bad_signature() -> None:
    root = _make_root(0x40)
    cert = _mint_device(root, root, nbf=int(time.time()) - 10)
    headers = _headers(cert, root.ed_priv_hex)
    headers["x-starfish-sig"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    assert await _auth(headers) is None


@pytest.mark.asyncio
async def test_rejects_expired_cap() -> None:
    root = _make_root(0x50)
    # nbf+exp both in the past.
    cert = _mint_device(root, root, nbf=int(time.time()) - 7200, ttl=3600)
    assert await _auth(_headers(cert, root.ed_priv_hex)) is None


@pytest.mark.asyncio
async def test_rejects_replayed_nonce() -> None:
    root = _make_root(0x60)
    cert = _mint_device(root, root, nbf=int(time.time()) - 10)
    headers = _headers(cert, root.ed_priv_hex)
    nonce_cache = create_in_memory_nonce_cache()
    first = await _auth(headers, nonce_cache=nonce_cache)
    assert first == root.user_id
    # Same nonce again → replay rejection.
    second = await _auth(headers, nonce_cache=nonce_cache)
    assert second is None


@pytest.mark.asyncio
async def test_rejects_revoked_cap() -> None:
    root = _make_root(0x70)
    cert = _mint_device(root, root, nbf=int(time.time()) - 10)

    class _AllRevoked:
        def is_revoked(self, iss: str, cap_sub: str, cap_nonce: str) -> bool:
            return True

    assert await _auth(_headers(cert, root.ed_priv_hex), revocation_store=_AllRevoked()) is None


@pytest.mark.asyncio
async def test_rejects_forged_member_shape() -> None:
    # A member cap with multiple collections is rejected by the sharing
    # validator (member-multi-collection) — the same shape that /pull rejects.
    alice = _make_root(0x80)
    bob = _make_root(0x82)
    cert = _mint_member(
        alice, bob, nbf=int(time.time()) - 10, collections=["a", "b"]
    )
    assert await _auth(_headers(cert, bob.ed_priv_hex)) is None
