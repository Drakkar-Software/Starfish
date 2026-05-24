"""Plugin-host behavior of the cap-cert role resolver — Python mirror of plugin-host.test.ts.

When ``plugins`` is omitted, behavior is unchanged. When ``plugins`` is
provided, the resolver dispatches per-kind validators after the core
``verify_cap_cert`` checks. Strict-kind dispatch rejects unknown kinds;
non-strict falls through.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from starfish_protocol.cap import sign_cap_cert
from starfish_protocol.request_signing import sign_request
from starfish_server.auth.nonce_cache import create_in_memory_nonce_cache
from starfish_server.auth.revocation_store import create_in_memory_revocation_store
from starfish_server.plugins import ServerPlugin, default_server_plugin
from starfish_server.router.cap_resolver import (
    CapAuthError,
    create_cap_cert_role_resolver,
)


@dataclass
class _Root:
    ed_priv_hex: str
    ed_pub_hex: str
    user_id: str
    kem_pub_hex: str


def _make_root(seed: int) -> _Root:
    priv = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    pub_bytes = priv.public_key().public_bytes(
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
    user_id = hashlib.sha256(pub_bytes).hexdigest()[:32]
    return _Root(
        ed_priv_hex=priv_bytes.hex(),
        ed_pub_hex=pub_bytes.hex(),
        user_id=user_id,
        kem_pub_hex=kem_pub.hex(),
    )


def _build_signed_device_cap(iss: _Root, sub: _Root) -> dict:
    nbf = int(time.time()) - 10
    unsigned = {
        "v": 1,
        "kind": "device",
        "issAlg": "ed25519",
        "iss": iss.ed_pub_hex,
        "issUserId": iss.user_id,
        "sub": sub.ed_pub_hex,
        "subKem": sub.kem_pub_hex,
        "scope": {"ops": ["read", "list"], "collections": ["*"], "paths": ["**"]},
        "nbf": nbf,
        "exp": nbf + 3600,
        "nonce": base64.b64encode(bytes([0xA1]) * 16).decode("ascii"),
    }
    return sign_cap_cert(unsigned, iss.ed_priv_hex)


def _build_signed_member_cap(iss: _Root, sub: _Root) -> dict:
    nbf = int(time.time()) - 10
    unsigned = {
        "v": 1,
        "kind": "member",
        "issAlg": "ed25519",
        "iss": iss.ed_pub_hex,
        "issUserId": iss.user_id,
        "sub": sub.ed_pub_hex,
        "subKem": sub.kem_pub_hex,
        "subUserId": sub.user_id,
        "scope": {
            "ops": ["read", "list"],
            "collections": ["shared"],
            "paths": ["shared/**", "!shared/_members"],
        },
        "nbf": nbf,
        "exp": nbf + 3600,
        "nonce": base64.b64encode(bytes([0xB2]) * 16).decode("ascii"),
    }
    return sign_cap_cert(unsigned, iss.ed_priv_hex)


class _FakeURL:
    def __init__(self, url: str) -> None:
        self._url = url
        parts = urlsplit(url)
        self.path = parts.path
        self.query = parts.query

    def __str__(self) -> str:
        return self._url


class _FakeRequest:
    def __init__(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> None:
        self.method = method
        self.url = _FakeURL(url)
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._body = body
        self.path_params: dict[str, str] = {}

    async def body(self) -> bytes:
        return self._body


def _cap_header(cert: dict) -> str:
    return "Cap " + base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")


def _signed_request(cert: dict, sub: _Root) -> _FakeRequest:
    # Bind the signature to the same host the resolver reconstructs from
    # the inbound URL.
    sig = sign_request(
        "GET", "/pull/notes/abc", b"", sub.ed_priv_hex, host="api"
    )
    return _FakeRequest(
        "GET",
        "https://api/pull/notes/abc",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": str(sig.ts),
            "X-Starfish-Nonce": sig.nonce,
        },
    )


@pytest.mark.asyncio
async def test_no_plugins_legacy_path_unchanged() -> None:
    alice = _make_root(0x11)
    cert = _build_signed_device_cap(alice, alice)
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    result = await resolver(_signed_request(cert, alice))
    assert result.identity == alice.user_id


@pytest.mark.asyncio
async def test_default_server_plugin_accepts_device_cap() -> None:
    alice = _make_root(0x12)
    cert = _build_signed_device_cap(alice, alice)
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        plugins=[default_server_plugin],
    )
    result = await resolver(_signed_request(cert, alice))
    assert result.identity == alice.user_id


@pytest.mark.asyncio
async def test_default_server_plugin_rejects_member_cap() -> None:
    # default_server_plugin is device-only; a member cap has no validator.
    alice = _make_root(0x21)
    bob = _make_root(0x22)
    cert = _build_signed_member_cap(alice, bob)
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        plugins=[default_server_plugin],
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(_signed_request(cert, bob))
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_strict_dispatch_rejects_unregistered_kind() -> None:
    alice = _make_root(0x13)
    cert = _build_signed_device_cap(alice, alice)
    member_only = ServerPlugin(name="member-only", cap_validators={"member": lambda _: None})
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        plugins=[member_only],
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(_signed_request(cert, alice))
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_non_strict_dispatch_falls_through_for_unregistered_kind() -> None:
    alice = _make_root(0x14)
    cert = _build_signed_device_cap(alice, alice)
    member_only = ServerPlugin(name="member-only", cap_validators={"member": lambda _: None})
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        plugins=[member_only],
        strict_kind_dispatch=False,
    )
    result = await resolver(_signed_request(cert, alice))
    assert result.identity == alice.user_id


@pytest.mark.asyncio
async def test_validator_throw_rejects_401_with_message() -> None:
    alice = _make_root(0x15)
    cert = _build_signed_device_cap(alice, alice)

    def _raise(_cert):
        raise ValueError("custom-policy-violation")

    failing = ServerPlugin(name="failing", cap_validators={"device": _raise})
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        plugins=[failing],
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(_signed_request(cert, alice))
    assert exc.value.status == 401
    assert "custom-policy-violation" in str(exc.value)


@pytest.mark.asyncio
async def test_multiple_plugins_compose_in_order_first_throw_rejects() -> None:
    alice = _make_root(0x16)
    cert = _build_signed_device_cap(alice, alice)
    calls: list[str] = []

    def _ok(_cert):
        calls.append("ok")

    def _fail(_cert):
        calls.append("fail")
        raise ValueError("policy-X")

    ok = ServerPlugin(name="ok", cap_validators={"device": _ok})
    fail = ServerPlugin(name="fail", cap_validators={"device": _fail})
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        plugins=[ok, fail],
    )
    with pytest.raises(CapAuthError):
        await resolver(_signed_request(cert, alice))
    assert calls == ["ok", "fail"]


@pytest.mark.asyncio
async def test_anonymous_short_circuits_to_public_regardless_of_plugins() -> None:
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        plugins=[default_server_plugin],
        allow_anonymous=True,
    )
    req = _FakeRequest("GET", "https://api/pull/notes/abc", headers={})
    result = await resolver(req)
    assert result.identity == ""
    assert "public" in result.roles
