"""End-to-end tests for the cap-cert role resolver."""

import base64
import hashlib
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from starfish_sharing import sharing_server_plugin
from starfish_protocol.cap import sign_cap_cert
from starfish_protocol.hash import stable_stringify
from starfish_protocol.plugins import ServerPlugin
from starfish_protocol.request_signing import sign_request
from starfish_protocol.revocation import revocation_list_canonical_signing_input
from starfish_server.auth.nonce_cache import create_in_memory_nonce_cache
from starfish_server.auth.revocation_store import create_in_memory_revocation_store
from starfish_server.router.cap_resolver import (
    CapAuthError,
    create_cap_cert_role_resolver,
)


@dataclass
class _Root:
    ed_priv: Ed25519PrivateKey
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
    pub_hex = pub_bytes.hex()
    user_id = hashlib.sha256(pub_bytes).hexdigest()[:32]
    kem_priv = X25519PrivateKey.from_private_bytes(bytes([seed + 1]) * 32)
    kem_pub_bytes = kem_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return _Root(
        ed_priv=priv,
        ed_priv_hex=priv_bytes.hex(),
        ed_pub_hex=pub_hex,
        user_id=user_id,
        kem_pub_hex=kem_pub_bytes.hex(),
    )


def _mint_device(iss: _Root, sub: _Root, nbf: int, ttl: int = 3600) -> dict:
    unsigned = {
        "v": 1,
        "kind": "device",
        "iss": iss.ed_pub_hex,
        "issUserId": iss.user_id,
        "sub": sub.ed_pub_hex,
        "subKem": sub.kem_pub_hex,
        "scope": {
            "ops": ["read", "write", "list"],
            "collections": ["notes"],
            "paths": ["notes/*"],
        },
        "nbf": nbf,
        "exp": nbf + ttl,
        "nonce": base64.b64encode(bytes([7]) * 16).decode("ascii"),
    }
    return sign_cap_cert(unsigned, iss.ed_priv_hex)


def _mint_member(iss: _Root, sub: _Root, nbf: int, ttl: int = 3600) -> dict:
    unsigned = {
        "v": 1,
        "kind": "member",
        "iss": iss.ed_pub_hex,
        "issUserId": iss.user_id,
        "sub": sub.ed_pub_hex,
        "subKem": sub.kem_pub_hex,
        "subUserId": sub.user_id,
        "scope": {
            "ops": ["read", "write"],
            "collections": ["shared"],
            "paths": ["shared/{identity}/*"],
        },
        "nbf": nbf,
        "exp": nbf + ttl,
        "nonce": base64.b64encode(bytes([3]) * 16).decode("ascii"),
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
    """Minimal stand-in for Starlette's Request used by the resolver."""

    def __init__(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> None:
        self.method = method
        self.url = _FakeURL(url)
        # Case-insensitive headers: store lowercase keys
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._body = body

    async def body(self) -> bytes:
        return self._body


def _cap_header(cert: dict) -> str:
    import json

    return "Cap " + base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")


@pytest.mark.asyncio
async def test_device_cap_returns_iss_user_id_and_cap_roles() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    now_sec = int(time.time())
    cert = _mint_device(alice, dev, now_sec - 10)

    sig = sign_request(
        "POST", "/push/notes/abc", b"{}", dev.ed_priv_hex, host="api.example.com"
    )
    req = _FakeRequest(
        method="POST",
        url="https://api.example.com/push/notes/abc",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": str(sig.ts),
            "X-Starfish-Nonce": sig.nonce,
            "Content-Length": "2",
        },
        body=b"{}",
    )
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    auth = await resolver(req)
    assert auth.identity == alice.user_id
    assert "cap:write:notes" in auth.roles
    assert "cap:read:notes" in auth.roles
    assert "cap:list:notes" in auth.roles
    # `self` is NOT emitted by the resolver — the route-builder adds it
    # conditionally on `params.identity == auth.identity`. The path here
    # has no `{identity}` param, so `self` must be absent.
    assert "self" not in auth.roles


@pytest.mark.asyncio
async def test_non_integer_timestamp_rejected_identically_to_typescript() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    # "0x10"/"1e3"/"12.5" were already rejected by int(); " 12"/"1_000"/"+12"
    # were silently accepted by int() before the shared regex guard, diverging
    # from JS Number(). All must now be rejected with the same error.
    for bad_ts in ("0x10", "1e3", "12.5", " 12", "1_000", "+12"):
        req = _FakeRequest(
            method="POST",
            url="https://api.example.com/push/notes/abc",
            headers={
                "Authorization": _cap_header(cert),
                "X-Starfish-Sig": "AA",
                "X-Starfish-Ts": bad_ts,
                "X-Starfish-Nonce": "AA",
                "Content-Length": "2",
            },
            body=b"{}",
        )
        with pytest.raises(CapAuthError) as exc:
            await resolver(req)
        assert "X-Starfish-Ts" in str(exc.value)


@pytest.mark.asyncio
async def test_unicode_digit_timestamp_rejected_identically_to_typescript() -> None:
    # _parse_integer_header now uses the ASCII class [0-9] (not Unicode-aware \d),
    # so a Ts header transcoded to non-ASCII decimal digits (e.g. Arabic-Indic) is
    # rejected at parse with 'invalid X-Starfish-Ts' — matching the TypeScript
    # resolver. Before the fix, Python's \d + int() parsed it to the SAME integer
    # and the request authenticated, a cross-language divergence.
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    sig = sign_request(
        "POST", "/push/notes/abc", b"{}", dev.ed_priv_hex, host="api.example.com"
    )
    # Transcode the signed (ASCII) timestamp to Arabic-Indic digits.
    unicode_ts = str(sig.ts).translate(str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩"))
    req = _FakeRequest(
        method="POST",
        url="https://api.example.com/push/notes/abc",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": unicode_ts,
            "X-Starfish-Nonce": sig.nonce,
            "Content-Length": "2",
        },
        body=b"{}",
    )
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    with pytest.raises(CapAuthError, match="X-Starfish-Ts"):
        await resolver(req)


@pytest.mark.asyncio
async def test_missing_auth_anonymous_default_true() -> None:
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    req = _FakeRequest("GET", "https://x/y")
    auth = await resolver(req)
    assert auth.identity == ""
    assert auth.roles == ["public"]


@pytest.mark.asyncio
async def test_missing_auth_disallowed_raises_401() -> None:
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        allow_anonymous=False,
    )
    req = _FakeRequest("GET", "https://x/y")
    with pytest.raises(CapAuthError) as exc:
        await resolver(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_bad_cap_signature_raises_401() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    tampered = {**cert, "sig": base64.b64encode(bytes(64)).decode("ascii")}
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    req = _FakeRequest(
        "GET",
        "https://api/foo",
        headers={
            "Authorization": _cap_header(tampered),
            "X-Starfish-Sig": "x",
            "X-Starfish-Ts": str(int(time.time() * 1000)),
            "X-Starfish-Nonce": "n",
        },
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_bad_request_signature_raises_401() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    req = _FakeRequest(
        "GET",
        "https://api/foo",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": base64.b64encode(bytes(64)).decode("ascii"),
            "X-Starfish-Ts": str(int(time.time() * 1000)),
            "X-Starfish-Nonce": base64.b64encode(bytes(16)).decode("ascii"),
        },
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_replayed_nonce_raises_401() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    sig = sign_request("GET", "/pull/notes/abc", b"", dev.ed_priv_hex, host="api")
    headers = {
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
    }
    req1 = _FakeRequest("GET", "https://api/pull/notes/abc", headers=headers)
    auth1 = await resolver(req1)
    assert auth1.identity == alice.user_id

    req2 = _FakeRequest("GET", "https://api/pull/notes/abc", headers=headers)
    with pytest.raises(CapAuthError) as exc:
        await resolver(req2)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_expired_cap_raises_401() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    # Far in the past + tiny TTL → outside even default 300s skew
    nbf = int(time.time()) - 100_000
    cert = _mint_device(alice, dev, nbf, ttl=10)
    sig = sign_request("GET", "/pull/notes/x", b"", dev.ed_priv_hex, host="api")
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    req = _FakeRequest(
        "GET",
        "https://api/pull/notes/x",
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


@pytest.mark.asyncio
async def test_member_cap_returns_sub_user_id_and_delegated_role() -> None:
    alice = _make_root(0x42)
    bob = _make_root(0x99)
    cert = _mint_member(alice, bob, int(time.time()) - 10)
    # scope.paths is `shared/{identity}/*` and `{identity}` is expanded
    # server-side to `bob.user_id`; the URL must hit that path.
    req_path = f"/pull/shared/{bob.user_id}/abc"
    sig = sign_request("GET", req_path, b"", bob.ed_priv_hex, host="api")
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        # member caps require a registered validator (device-only by default).
        plugins=[sharing_server_plugin],
    )
    req = _FakeRequest(
        "GET",
        f"https://api{req_path}",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": str(sig.ts),
            "X-Starfish-Nonce": sig.nonce,
        },
    )
    auth = await resolver(req)
    assert auth.identity == bob.user_id
    assert f"delegated:{alice.user_id}:shared" in auth.roles
    assert "cap:read:shared" in auth.roles
    assert "cap:write:shared" in auth.roles


# --- pre-auth body buffer (DoS amplifier) ---


class _FakeRequestTrackingBody(_FakeRequest):
    """Variant of ``_FakeRequest`` that flips a flag if ``body()`` is awaited."""

    def __init__(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> None:
        super().__init__(method, url, headers, body)
        self.body_called = False

    async def body(self) -> bytes:
        self.body_called = True
        return self._body


@pytest.mark.asyncio
async def test_rejects_413_when_content_length_exceeds_max() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    req = _FakeRequestTrackingBody(
        "POST",
        "https://api/push/notes/abc",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": "x",
            "X-Starfish-Ts": str(int(time.time() * 1000)),
            "X-Starfish-Nonce": "n",
            "Content-Length": "100000000",
        },
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(req)
    assert exc.value.status == 413
    # Body must NOT have been read.
    assert req.body_called is False


@pytest.mark.asyncio
async def test_rejects_413_when_content_length_absent_on_write() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    req = _FakeRequest(
        "POST",
        "https://api/push/notes/abc",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": "x",
            "X-Starfish-Ts": str(int(time.time() * 1000)),
            "X-Starfish-Nonce": "n",
            # no Content-Length
        },
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(req)
    assert exc.value.status == 413


@pytest.mark.asyncio
async def test_honours_explicit_max_body_bytes() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        max_body_bytes=16,
    )
    req = _FakeRequest(
        "POST",
        "https://api/push/notes/abc",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": "x",
            "X-Starfish-Ts": str(int(time.time() * 1000)),
            "X-Starfish-Nonce": "n",
            "Content-Length": "32",
        },
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(req)
    assert exc.value.status == 413


# --- cap-cert verify ordering (cheap checks first) ---


@pytest.mark.asyncio
async def test_missing_sig_headers_rejected_before_cap_verify() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    # Tamper with cap-cert signature — if the resolver verified the cap
    # *before* checking the cheap header presence, we'd see a "bad-signature"
    # error instead of "missing request signature headers".
    tampered = {**cert, "sig": base64.b64encode(bytes(64)).decode("ascii")}
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    req = _FakeRequest(
        "GET",
        "https://api/foo",
        headers={"Authorization": _cap_header(tampered)},
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(req)
    assert exc.value.status == 401
    assert "missing request signature headers" in str(exc.value)


# --- Authorization header length cap ---


@pytest.mark.asyncio
async def test_rejects_oversized_cap_header() -> None:
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        max_cap_header_bytes=8192,
    )
    big = "A" * 10_000
    req = _FakeRequest(
        "GET",
        "https://api/x",
        headers={"Authorization": f"Cap {big}"},
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(req)
    assert exc.value.status == 401
    assert "cap-too-large" in str(exc.value)


@pytest.mark.asyncio
async def test_accepts_cap_header_within_limit() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    cap_hdr = _cap_header(cert)
    # Sanity: real cap-cert header well under default 8 KB
    assert len(cap_hdr) < 8192

    sig = sign_request("GET", "/pull/notes/abc", b"", dev.ed_priv_hex, host="api")
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    req = _FakeRequest(
        "GET",
        "https://api/pull/notes/abc",
        headers={
            "Authorization": cap_hdr,
            "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": str(sig.ts),
            "X-Starfish-Nonce": sig.nonce,
        },
    )
    auth = await resolver(req)
    assert auth.identity == alice.user_id


@pytest.mark.asyncio
async def test_revoked_cap_raises_401() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)

    rev_store = create_in_memory_revocation_store()
    unsigned = {
        "v": 1,
        "iss": alice.ed_pub_hex,
        "issUserId": alice.user_id,
        "generation": 1,
        "revoked": [
            {"sub": cert["sub"], "nonce": cert["nonce"], "exp": cert["exp"]}
        ],
    }
    canonical = revocation_list_canonical_signing_input(unsigned).encode("utf-8")
    sig_bytes = alice.ed_priv.sign(canonical)
    list_signed = {**unsigned, "sig": base64.b64encode(sig_bytes).decode("ascii")}
    assert rev_store.accept_list(list_signed)["ok"] is True

    sig = sign_request("GET", "/pull/notes/x", b"", dev.ed_priv_hex, host="api")
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=rev_store,
    )
    req = _FakeRequest(
        "GET",
        "https://api/pull/notes/x",
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


# ── Parsing & input-validation hardening tests ───────────────────────────────


def _cap_header(cert: dict) -> str:
    return "Cap " + base64.b64encode(stable_stringify(cert).encode("utf-8")).decode("ascii")


def _base_resolver():
    return create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )


@pytest.mark.asyncio
async def test_header_missing_allow_anonymous_returns_public() -> None:
    auth = await _base_resolver()(_FakeRequest("GET", "https://x/y"))
    assert "public" in auth.roles
    assert auth.identity == ""


@pytest.mark.asyncio
async def test_header_missing_strict_rejects_401() -> None:
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        allow_anonymous=False,
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(_FakeRequest("GET", "https://x/y"))
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_header_unknown_scheme_anonymous_default() -> None:
    req = _FakeRequest("GET", "https://x/y", headers={"Authorization": "Bearer notacap"})
    auth = await _base_resolver()(req)
    assert "public" in auth.roles


@pytest.mark.asyncio
async def test_header_unknown_scheme_strict_rejects_401() -> None:
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        allow_anonymous=False,
    )
    req = _FakeRequest("GET", "https://x/y", headers={"Authorization": "Bearer notacap"})
    with pytest.raises(CapAuthError) as exc:
        await resolver(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_cap_payload_invalid_base64_rejects() -> None:
    req = _FakeRequest("GET", "https://x/y", headers={"Authorization": "Cap !@#$%^&*()"})
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_cap_payload_non_json_rejects() -> None:
    garbage = base64.b64encode(b"not json at all").decode("ascii")
    req = _FakeRequest("GET", "https://x/y", headers={"Authorization": f"Cap {garbage}"})
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_cap_payload_missing_required_fields_rejects() -> None:
    partial = base64.b64encode(b'{"v":1}').decode("ascii")
    req = _FakeRequest("GET", "https://x/y", headers={"Authorization": f"Cap {partial}"})
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_cap_header_over_8kb_rejected() -> None:
    oversize = "A" * 9_000
    req = _FakeRequest("GET", "https://x/y", headers={"Authorization": f"Cap {oversize}"})
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_sig_header_missing_rejects() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    req = _FakeRequest("GET", "https://api/pull/notes/x", headers={
        "Authorization": _cap_header(cert),
        "X-Starfish-Ts": str(int(time.time() * 1000)),
        "X-Starfish-Nonce": base64.b64encode(bytes(16)).decode("ascii"),
    })
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_ts_header_missing_rejects() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    sig = sign_request("GET", "/pull/notes/x", b"", dev.ed_priv_hex, host="api")
    req = _FakeRequest("GET", "https://api/pull/notes/x", headers={
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Nonce": sig.nonce,
    })
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_nonce_header_missing_rejects() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    sig = sign_request("GET", "/pull/notes/x", b"", dev.ed_priv_hex, host="api")
    req = _FakeRequest("GET", "https://api/pull/notes/x", headers={
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
    })
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_ts_non_numeric_rejects() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    sig = sign_request("GET", "/pull/notes/x", b"", dev.ed_priv_hex, host="api")
    req = _FakeRequest("GET", "https://api/pull/notes/x", headers={
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": "not-a-number",
        "X-Starfish-Nonce": sig.nonce,
    })
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_ts_outside_clock_skew_rejects() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    far_past = int(time.time() * 1000) - 30 * 60 * 1000
    sig = sign_request("GET", "/pull/notes/x", b"", dev.ed_priv_hex, ts=far_past)
    req = _FakeRequest("GET", "https://api/pull/notes/x", headers={
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
    })
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_get_does_not_require_content_length() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    sig = sign_request("GET", "/pull/notes/abc", b"", dev.ed_priv_hex, host="api")
    req = _FakeRequest("GET", "https://api/pull/notes/abc", headers={
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
    })
    auth = await _base_resolver()(req)
    assert auth.identity == alice.user_id


@pytest.mark.asyncio
async def test_post_with_valid_content_length_succeeds() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    body = b'{"hello":"world"}'
    sig = sign_request("POST", "/push/notes/abc", body, dev.ed_priv_hex, host="api")
    req = _FakeRequest("POST", "https://api/push/notes/abc",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": str(sig.ts),
            "X-Starfish-Nonce": sig.nonce,
            "Content-Length": str(len(body)),
        }, body=body,
    )
    auth = await _base_resolver()(req)
    assert auth.identity == alice.user_id


@pytest.mark.asyncio
async def test_post_content_length_malformed_rejects_413() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    sig = sign_request("POST", "/push/notes/abc", b"{}", dev.ed_priv_hex)
    req = _FakeRequest("POST", "https://api/push/notes/abc",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": str(sig.ts),
            "X-Starfish-Nonce": sig.nonce,
            "Content-Length": "abc",
        }, body=b"{}",
    )
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 413


@pytest.mark.asyncio
async def test_post_content_length_negative_rejects_413() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    sig = sign_request("POST", "/push/notes/abc", b"{}", dev.ed_priv_hex)
    req = _FakeRequest("POST", "https://api/push/notes/abc",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": str(sig.ts),
            "X-Starfish-Nonce": sig.nonce,
            "Content-Length": "-5",
        }, body=b"{}",
    )
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 413


@pytest.mark.asyncio
async def test_content_length_canonicalization_and_leading_zeros() -> None:
    """``Content-Length`` is parsed by the SAME shared ``-?\\d+`` rule as ``X-Starfish-Ts``.

    Non-canonical forms that ``int()`` would accept (``+64``, ``1_000``, whitespace) and
    JS ``Number()``-only forms (``0x10``, ``1e3``, ``12.5``) are rejected 413 on both the
    Python and TS servers, so a request can never authenticate with a body-size header
    one runtime reads differently from the other. Leading zeros are the lone
    non-canonical form the shared rule *accepts* (the string equals its base-10 value),
    so a tiny body advertising ``00000064`` still authenticates — pinned so a future
    "tighten to strictly canonical" change is a deliberate one, not an accident.
    """
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    sig = sign_request("POST", "/push/notes/abc", b"{}", dev.ed_priv_hex, host="api")

    def _req(content_length: str) -> _FakeRequest:
        return _FakeRequest(
            "POST",
            "https://api/push/notes/abc",
            headers={
                "Authorization": _cap_header(cert),
                "X-Starfish-Sig": sig.sig,
                "X-Starfish-Ts": str(sig.ts),
                "X-Starfish-Nonce": sig.nonce,
                "Content-Length": content_length,
            },
            body=b"{}",
        )

    for bad_cl in ("+64", " 64", "64 ", "1_000", "0x10", "1e3", "12.5", ""):
        with pytest.raises(CapAuthError) as exc:
            await _base_resolver()(_req(bad_cl))
        assert exc.value.status == 413, f"{bad_cl!r} should be rejected 413"

    # Leading zeros parse to the same base-10 value (64) and are accepted.
    auth = await _base_resolver()(_req("00000064"))
    assert auth.identity == alice.user_id


def _mint_with_paths(iss, sub, nbf, paths, ttl=3600):
    unsigned = {
        "v": 1, "kind": "device",
        "iss": iss.ed_pub_hex, "issUserId": iss.user_id,
        "sub": sub.ed_pub_hex, "subKem": sub.kem_pub_hex,
        "scope": {"ops": ["read","write","list"], "collections": ["notes"], "paths": paths},
        "nbf": nbf, "exp": nbf + ttl,
        "nonce": base64.b64encode(bytes([8]) * 16).decode("ascii"),
    }
    return sign_cap_cert(unsigned, iss.ed_priv_hex)


@pytest.mark.asyncio
async def test_glob_single_star_does_not_span_slash() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_with_paths(alice, dev, int(time.time()) - 10, ["notes/*"])
    sig = sign_request("GET", "/pull/notes/abc/deep", b"", dev.ed_priv_hex, host="api")
    req = _FakeRequest("GET", "https://api/pull/notes/abc/deep", headers={
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
    })
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 403


@pytest.mark.asyncio
async def test_glob_double_star_spans_slashes() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_with_paths(alice, dev, int(time.time()) - 10, ["notes/**"])
    sig = sign_request("GET", "/pull/notes/abc/deep", b"", dev.ed_priv_hex, host="api")
    req = _FakeRequest("GET", "https://api/pull/notes/abc/deep", headers={
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
    })
    auth = await _base_resolver()(req)
    assert auth.identity == alice.user_id


@pytest.mark.asyncio
async def test_glob_deny_beats_wildcard_allow() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_with_paths(alice, dev, int(time.time()) - 10, ["notes/*", "!notes/_keyring"])
    sig = sign_request("GET", "/pull/notes/_keyring", b"", dev.ed_priv_hex, host="api")
    req = _FakeRequest("GET", "https://api/pull/notes/_keyring", headers={
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
    })
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 403


@pytest.mark.asyncio
async def test_glob_only_denies_rejects() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_with_paths(alice, dev, int(time.time()) - 10, ["!notes/_keyring"])
    sig = sign_request("GET", "/pull/notes/abc", b"", dev.ed_priv_hex, host="api")
    req = _FakeRequest("GET", "https://api/pull/notes/abc", headers={
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
    })
    with pytest.raises(CapAuthError) as exc:
        await _base_resolver()(req)
    assert exc.value.status == 403


@pytest.mark.asyncio
async def test_headers_case_insensitive() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)
    sig = sign_request("GET", "/pull/notes/abc", b"", dev.ed_priv_hex, host="api")
    req = _FakeRequest("GET", "https://api/pull/notes/abc", headers={
        "authorization": _cap_header(cert),
        "x-starfish-sig": sig.sig,
        "X-STARFISH-TS": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
    })
    auth = await _base_resolver()(req)
    assert auth.identity == alice.user_id


@pytest.mark.asyncio
async def test_blob_upload_signed_with_empty_body_is_accepted() -> None:
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    now_sec = int(time.time())
    cert = _mint_device(alice, dev, now_sec - 10)

    # Binary blob uploads are signed with an EMPTY body — the client's push_blob
    # passes body=None, since clients don't fold large/streamed blob bytes into
    # the per-request signature (blob integrity comes from the content seal).
    sig = sign_request("POST", "/push/notes/blob1", b"", dev.ed_priv_hex, host="api.example.com")
    blob = bytes([0, 0, 0, 1, 9, 8, 7, 6, 5, 4, 3, 2, 1])
    req = _FakeRequest(
        method="POST",
        url="https://api.example.com/push/notes/blob1",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": str(sig.ts),
            "X-Starfish-Nonce": sig.nonce,
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(blob)),
        },
        body=blob,
    )
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    auth = await resolver(req)
    assert auth.identity == alice.user_id
    assert "cap:write:notes" in auth.roles


@pytest.mark.asyncio
async def test_non_octet_binary_blob_signed_with_empty_body_is_accepted() -> None:
    # The client signs ANY blob with an empty body, not just octet-stream — so the
    # server treats any non-JSON content type as a blob upload. Mirrors cap-resolver.test.ts.
    alice = _make_root(0x42)
    dev = _make_root(0x11)
    cert = _mint_device(alice, dev, int(time.time()) - 10)

    sig = sign_request("POST", "/push/notes/avatar", b"", dev.ed_priv_hex, host="api.example.com")
    blob = bytes([137, 80, 78, 71, 13, 10, 26, 10])  # PNG magic
    req = _FakeRequest(
        method="POST",
        url="https://api.example.com/push/notes/avatar",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": str(sig.ts),
            "X-Starfish-Nonce": sig.nonce,
            "Content-Type": "image/png",
            "Content-Length": str(len(blob)),
        },
        body=blob,
    )
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
    )
    auth = await resolver(req)
    assert auth.identity == alice.user_id
    assert "cap:write:notes" in auth.roles


@pytest.mark.asyncio
async def test_member_cap_with_no_scope_paths_rejected_at_resolver() -> None:
    """Defense-in-depth: the resolver rejects a member cap with no scope.paths
    even if a (permissive) plugin skips the mint/shape barrier. Wire a plugin
    that registers `member` WITHOUT the barrier so the cap reaches the resolver
    path gate. A device cap with no paths stays allowed. Mirrors the TS twin in
    cap-resolver.test.ts."""
    alice = _make_root(0x42)
    bob = _make_root(0x11)
    now_sec = int(time.time())
    unsigned = {
        "v": 1,
        "kind": "member",
        "iss": alice.ed_pub_hex,
        "issUserId": alice.user_id,
        "sub": bob.ed_pub_hex,
        "subKem": bob.kem_pub_hex,
        "subUserId": bob.user_id,
        "scope": {"ops": ["read", "write", "list"], "collections": ["notes"]},  # no paths
        "nbf": now_sec - 10,
        "exp": now_sec + 3600,
        "nonce": base64.b64encode(bytes([9]) * 16).decode("ascii"),
    }
    cert = sign_cap_cert(unsigned, alice.ed_priv_hex)
    sig = sign_request("GET", "/pull/notes/anything", b"", bob.ed_priv_hex, host="api")
    req = _FakeRequest(
        "GET",
        "https://api/pull/notes/anything",
        headers={
            "Authorization": _cap_header(cert),
            "X-Starfish-Sig": sig.sig,
            "X-Starfish-Ts": str(sig.ts),
            "X-Starfish-Nonce": sig.nonce,
        },
    )
    permissive = ServerPlugin(
        name="permissive-member", cap_validators={"member": lambda cert: None}
    )
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        plugins=[permissive],
    )
    with pytest.raises(CapAuthError) as exc:
        await resolver(req)
    assert exc.value.status == 403
    assert "scope.paths" in str(exc.value)
