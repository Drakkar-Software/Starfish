"""Member-cap structural bounds — Python mirror of member-cap-bounds.test.ts.

Both the well-formedness assertion (used by ``mint_member_cap``) and the
server verifier (``verify_cap_cert``) must catch forbidden member-cap
shapes:

- Path that lands in the issuer's ``users/<issUserId>/`` namespace.
- Wildcard collection (``"*"``).
- ``subUserId == issUserId``.

The server-side cap-resolver must reject forged member caps that bypass
the client-side guardrails.
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
from urllib.parse import urlsplit

from starfish_protocol.cap import sign_cap_cert
from starfish_sharing.cap_mint import assert_member_cap_shape
from starfish_protocol.request_signing import sign_request
from starfish_server.auth.nonce_cache import create_in_memory_nonce_cache
from starfish_server.auth.revocation_store import create_in_memory_revocation_store
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
    kem_priv = X25519PrivateKey.from_private_bytes(bytes([seed + 1]) * 32)
    kem_pub = kem_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    user_id = hashlib.sha256(pub_bytes).hexdigest()[:32]
    return _Root(
        ed_priv_hex=priv_bytes.hex(),
        ed_pub_hex=pub_bytes.hex(),
        user_id=user_id,
        kem_pub_hex=kem_pub.hex(),
    )


def _build_unsigned_member(
    iss: _Root,
    sub: _Root,
    scope: dict,
    nonce_seed: int = 7,
) -> dict:
    nbf = int(time.time()) - 10
    return {
        "v": 1,
        "kind": "member",
        "iss": iss.ed_pub_hex,
        "issUserId": iss.user_id,
        "sub": sub.ed_pub_hex,
        "subKem": sub.kem_pub_hex,
        "subUserId": sub.user_id,
        "scope": scope,
        "nbf": nbf,
        "exp": nbf + 3600,
        "nonce": base64.b64encode(bytes([nonce_seed]) * 16).decode("ascii"),
    }


# ── Client-side mint guardrails (assert_cap_cert_well_formed) ────────────────


def test_assert_throws_member_private_path() -> None:
    alice = _make_root(0x61)
    bob = _make_root(0x62)
    unsigned = _build_unsigned_member(
        alice,
        bob,
        {
            "ops": ["read", "write"],
            "collections": ["users"],
            "paths": ["users/{identity}/private"],
        },
    )
    with pytest.raises(ValueError) as exc:
        assert_member_cap_shape(unsigned)
    assert exc.value.args[0] == "member-private-path"


def test_assert_throws_member_wildcard_collections() -> None:
    alice = _make_root(0x63)
    bob = _make_root(0x64)
    unsigned = _build_unsigned_member(
        alice,
        bob,
        {"ops": ["read"], "collections": ["*"]},
    )
    with pytest.raises(ValueError) as exc:
        assert_member_cap_shape(unsigned)
    assert exc.value.args[0] == "member-wildcard-collections"


def test_assert_throws_member_self() -> None:
    alice = _make_root(0x65)
    alice_clone = _make_root(0x65)
    assert alice.user_id == alice_clone.user_id
    unsigned = _build_unsigned_member(
        alice,
        alice_clone,
        {"ops": ["read"], "collections": ["shared"]},
    )
    with pytest.raises(ValueError) as exc:
        assert_member_cap_shape(unsigned)
    assert exc.value.args[0] == "member-self"


# ── Structural barrier (assert_member_cap_shape, owned by starfish_sharing) ──
# Forged caps bypass the client guardrail (sign_cap_cert does not validate
# shape); the sharing plugin re-runs assert_member_cap_shape server-side.


def test_shape_rejects_forged_member_private_path() -> None:
    alice = _make_root(0x71)
    bob = _make_root(0x72)
    unsigned = _build_unsigned_member(
        alice,
        bob,
        {
            "ops": ["read"],
            "collections": ["users"],
            "paths": ["users/{identity}/private"],
        },
        nonce_seed=0x71,
    )
    cert = sign_cap_cert(unsigned, alice.ed_priv_hex)
    with pytest.raises(ValueError) as exc:
        assert_member_cap_shape(cert)
    assert exc.value.args[0] == "member-private-path"


def test_shape_rejects_forged_member_wildcard_collections() -> None:
    alice = _make_root(0x73)
    bob = _make_root(0x74)
    unsigned = _build_unsigned_member(
        alice,
        bob,
        {"ops": ["read"], "collections": ["*"]},
        nonce_seed=0x72,
    )
    cert = sign_cap_cert(unsigned, alice.ed_priv_hex)
    with pytest.raises(ValueError) as exc:
        assert_member_cap_shape(cert)
    assert exc.value.args[0] == "member-wildcard-collections"


def test_shape_rejects_forged_member_self() -> None:
    alice = _make_root(0x75)
    unsigned = _build_unsigned_member(
        alice,
        alice,
        {"ops": ["read"], "collections": ["shared"]},
        nonce_seed=0x73,
    )
    cert = sign_cap_cert(unsigned, alice.ed_priv_hex)
    with pytest.raises(ValueError) as exc:
        assert_member_cap_shape(cert)
    assert exc.value.args[0] == "member-self"


# ── Resolver rejects forged caps (end-to-end) ───────────────────────────────


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
        path_params: dict[str, str] | None = None,
    ) -> None:
        self.method = method
        self.url = _FakeURL(url)
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._body = body
        self.path_params = path_params or {}

    async def body(self) -> bytes:
        return self._body


def _cap_header(cert: dict) -> str:
    return "Cap " + base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")


@pytest.mark.asyncio
async def test_resolver_rejects_forged_member_cap_via_authorization_header() -> None:
    alice = _make_root(0x81)
    bob = _make_root(0x82)
    unsigned = _build_unsigned_member(
        alice,
        bob,
        {"ops": ["read"], "collections": ["*"]},
        nonce_seed=0x81,
    )
    cert = sign_cap_cert(unsigned, alice.ed_priv_hex)
    # Sign with the SAME host the server extracts from the URL ("api"), so the
    # request signature is VALID and the rejection can only come from the
    # resolver's cap-cert handling — not an incidental host/sig mismatch.
    sig = sign_request("GET", "/pull/shared/abc", b"", bob.ed_priv_hex, host="api")
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    req = _FakeRequest(
        "GET",
        "https://api/pull/shared/abc",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": str(sig.ts),
            "X-Starfish-Nonce": sig.nonce,
        },
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(req)
    assert exc.value.status == 401


# ── cap-resolver is SECURE BY DEFAULT ────────────────────────────────────────
#
# The member-cap structural barriers live in ``assert_member_cap_shape``
# (starfish_sharing), wired via ``sharing_server_plugin``. A resolver built
# WITHOUT ``plugins`` previously skipped strict-kind dispatch entirely, so a
# forged member cap sailed through with baseline checks only. These tests sign
# the request with the correct host so the signature is valid — the resolver
# itself must do the rejecting.


async def _signed_headers_for(cert: dict, path_and_query: str, sub_ed_priv_hex: str) -> dict[str, str]:
    sig = sign_request("GET", path_and_query, b"", sub_ed_priv_hex, host="api")
    return {
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
    }


@pytest.mark.asyncio
async def test_forged_wildcard_member_cap_rejected_by_no_plugins_resolver() -> None:
    alice = _make_root(0x91)
    bob = _make_root(0x92)
    unsigned = _build_unsigned_member(
        alice,
        bob,
        {"ops": ["read", "write"], "collections": ["*"], "paths": ["**"]},
        nonce_seed=0x91,
    )
    cert = sign_cap_cert(unsigned, alice.ed_priv_hex)
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        # No ``plugins`` → device-only by default; ``member`` has no validator.
    )
    req = _FakeRequest(
        "GET",
        "https://api/pull/anything/x",
        headers=await _signed_headers_for(cert, "/pull/anything/x", bob.ed_priv_hex),
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_forged_keyring_write_member_cap_rejected_with_sharing_plugin() -> None:
    from starfish_sharing import sharing_server_plugin

    alice = _make_root(0x93)
    bob = _make_root(0x94)
    # ops include write; paths reach notes/_keyring with NO `!notes/_keyring` deny.
    unsigned = _build_unsigned_member(
        alice,
        bob,
        {"ops": ["read", "write"], "collections": ["notes"], "paths": ["notes/**"]},
        nonce_seed=0x93,
    )
    cert = sign_cap_cert(unsigned, alice.ed_priv_hex)
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        plugins=[sharing_server_plugin],
    )
    req = _FakeRequest(
        "GET",
        "https://api/pull/notes/x",
        headers=await _signed_headers_for(cert, "/pull/notes/x", bob.ed_priv_hex),
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_well_formed_member_cap_still_resolves_with_sharing_plugin() -> None:
    from starfish_sharing import sharing_server_plugin

    alice = _make_root(0x95)
    bob = _make_root(0x96)
    unsigned = _build_unsigned_member(
        alice,
        bob,
        {"ops": ["read", "list"], "collections": ["shared"], "paths": ["shared/**", "!shared/_members"]},
        nonce_seed=0x95,
    )
    cert = sign_cap_cert(unsigned, alice.ed_priv_hex)
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        plugins=[sharing_server_plugin],
    )
    req = _FakeRequest(
        "GET",
        "https://api/pull/shared/abc",
        headers=await _signed_headers_for(cert, "/pull/shared/abc", bob.ed_priv_hex),
    )
    auth = await resolver(req)
    assert auth.identity == bob.user_id
    assert f"delegated:{alice.user_id}:shared" in auth.roles
