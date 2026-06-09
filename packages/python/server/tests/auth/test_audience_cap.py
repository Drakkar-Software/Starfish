"""Resolver tests for the ``audience`` (public-link) cap kind.

Mirror of TS ``tests/router/audience-cap.test.ts``.
"""

import base64
import hashlib
import json
import pathlib
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from starfish_protocol.cap import user_id_from_pub_hex
from starfish_protocol.request_signing import sign_request
from starfish_protocol.revocation import build_revocation_list
from starfish_sharing import mint_audience_cap, mint_member_cap, scopes, sharing_server_plugin
from starfish_server.auth.nonce_cache import create_in_memory_nonce_cache
from starfish_server.auth.revocation_store import create_in_memory_revocation_store
from starfish_server.router.cap_resolver import CapAuthError, create_cap_cert_role_resolver


@dataclass
class _Key:
    ed_priv_hex: str
    ed_pub_hex: str
    user_id: str


def _make_key(seed: int) -> _Key:
    priv = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return _Key(
        ed_priv_hex=priv_bytes.hex(),
        ed_pub_hex=pub_bytes.hex(),
        user_id=hashlib.sha256(pub_bytes).hexdigest()[:32],
    )


ISSUER = _make_key(0x42)
_URL = "https://api.example.com/pull/broadcast/post-1"


class _FakeURL:
    def __init__(self, url: str) -> None:
        self._url = url
        parts = urlsplit(url)
        self.path = parts.path
        self.query = parts.query

    def __str__(self) -> str:
        return self._url


class _FakeRequest:
    def __init__(self, method: str, url: str, headers: dict[str, str]) -> None:
        self.method = method
        self.url = _FakeURL(url)
        self.headers = {k.lower(): v for k, v in headers.items()}

    async def body(self) -> bytes:
        return b""


def _cap_header(cert: dict) -> str:
    return "Cap " + base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")


def _redeem_headers(
    cert: dict,
    presenter: _Key,
    *,
    include_pub: bool = True,
    nonce: bytes | None = None,
    ts: int | None = None,
) -> dict[str, str]:
    parts = urlsplit(_URL)
    sig = sign_request(
        "GET",
        parts.path,
        b"",
        presenter.ed_priv_hex,
        host=parts.netloc,
        nonce=nonce,
        ts=ts,
    )
    headers = {
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
    }
    if include_pub:
        headers["X-Starfish-Pub"] = presenter.ed_pub_hex
    return headers


def _resolver(revocation_store=None):
    return create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=revocation_store or create_in_memory_revocation_store(),
        plugins=[sharing_server_plugin],
    )


def _now() -> int:
    return int(time.time())


def _open_cap() -> dict:
    from starfish_sharing import AudienceMintOpts

    return mint_audience_cap(
        ISSUER.ed_priv_hex,
        ISSUER.ed_pub_hex,
        "broadcast",
        scopes.read_only("broadcast"),
        AudienceMintOpts(nbf=_now() - 10, ttl_sec=3600),
    )


@pytest.mark.asyncio
async def test_open_cap_any_identity_authorized() -> None:
    cert = _open_cap()
    anyone = _make_key(0x71)
    auth = await _resolver()(_FakeRequest("GET", _URL, _redeem_headers(cert, anyone)))
    assert auth.identity == user_id_from_pub_hex(anyone.ed_pub_hex)
    assert "cap:read:broadcast" in auth.roles
    assert f"delegated:{ISSUER.user_id}:broadcast" in auth.roles


@pytest.mark.asyncio
async def test_restricted_cap_listed_identity_authorized() -> None:
    from starfish_sharing import AudienceMintOpts

    bob = _make_key(0x55)
    cert = mint_audience_cap(
        ISSUER.ed_priv_hex,
        ISSUER.ed_pub_hex,
        "broadcast",
        scopes.read_only("broadcast"),
        AudienceMintOpts(audience=[bob.ed_pub_hex], nbf=_now() - 10, ttl_sec=3600),
    )
    auth = await _resolver()(_FakeRequest("GET", _URL, _redeem_headers(cert, bob)))
    assert auth.identity == bob.user_id


@pytest.mark.asyncio
async def test_restricted_cap_non_listed_identity_rejected_403() -> None:
    from starfish_sharing import AudienceMintOpts

    bob = _make_key(0x55)
    mallory = _make_key(0x66)
    cert = mint_audience_cap(
        ISSUER.ed_priv_hex,
        ISSUER.ed_pub_hex,
        "broadcast",
        scopes.read_only("broadcast"),
        AudienceMintOpts(audience=[bob.ed_pub_hex], nbf=_now() - 10, ttl_sec=3600),
    )
    with pytest.raises(CapAuthError) as exc:
        await _resolver()(_FakeRequest("GET", _URL, _redeem_headers(cert, mallory)))
    assert exc.value.status == 403


@pytest.mark.asyncio
async def test_missing_pub_header_rejected_401() -> None:
    cert = _open_cap()
    anyone = _make_key(0x71)
    with pytest.raises(CapAuthError) as exc:
        await _resolver()(
            _FakeRequest("GET", _URL, _redeem_headers(cert, anyone, include_pub=False))
        )
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_malformed_pub_header_rejected_401() -> None:
    cert = _open_cap()
    anyone = _make_key(0x71)
    headers = _redeem_headers(cert, anyone)
    headers["X-Starfish-Pub"] = "NOT-HEX"
    with pytest.raises(CapAuthError) as exc:
        await _resolver()(_FakeRequest("GET", _URL, headers))
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_two_presenters_same_nonce_both_succeed() -> None:
    cert = _open_cap()
    a = _make_key(0x71)
    b = _make_key(0x72)
    r = _resolver()
    shared = bytes([0x5A]) * 16
    auth_a = await r(_FakeRequest("GET", _URL, _redeem_headers(cert, a, nonce=shared)))
    auth_b = await r(_FakeRequest("GET", _URL, _redeem_headers(cert, b, nonce=shared)))
    assert auth_a.identity == user_id_from_pub_hex(a.ed_pub_hex)
    assert auth_b.identity == user_id_from_pub_hex(b.ed_pub_hex)


@pytest.mark.asyncio
async def test_same_presenter_replay_rejected_401() -> None:
    cert = _open_cap()
    a = _make_key(0x71)
    r = _resolver()
    nonce = bytes([0x33]) * 16
    ts = int(time.time() * 1000)
    await r(_FakeRequest("GET", _URL, _redeem_headers(cert, a, nonce=nonce, ts=ts)))
    with pytest.raises(CapAuthError) as exc:
        await r(_FakeRequest("GET", _URL, _redeem_headers(cert, a, nonce=nonce, ts=ts)))
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_audience_cap_revoked_by_nonce_rejected_401() -> None:
    cert = _open_cap()
    anyone = _make_key(0x71)
    store = create_in_memory_revocation_store()
    rlist = build_revocation_list(
        ISSUER.ed_pub_hex,
        ISSUER.ed_priv_hex,
        1,
        [{"sub": "", "nonce": cert["nonce"], "exp": cert["exp"]}],
    )
    assert store.accept_list(rlist)["ok"] is True
    with pytest.raises(CapAuthError) as exc:
        await _resolver(store)(_FakeRequest("GET", _URL, _redeem_headers(cert, anyone)))
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_subject_wide_empty_sub_does_not_revoke_audience() -> None:
    # Footgun guard: an empty subject in `revokedSubjects` must not match the
    # subject-wide set, or every audience cap from the issuer would be revoked.
    cert = _open_cap()
    anyone = _make_key(0x71)
    store = create_in_memory_revocation_store()
    rlist = build_revocation_list(
        ISSUER.ed_pub_hex,
        ISSUER.ed_priv_hex,
        1,
        [],
        revoked_subjects=[{"sub": "", "exp": cert["exp"]}],
    )
    assert store.accept_list(rlist)["ok"] is True
    auth = await _resolver(store)(_FakeRequest("GET", _URL, _redeem_headers(cert, anyone)))
    assert auth.identity == user_id_from_pub_hex(anyone.ed_pub_hex)


@pytest.mark.asyncio
async def test_audience_cap_without_plugin_rejected_401() -> None:
    cert = _open_cap()
    anyone = _make_key(0x71)
    r = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        # no plugins → default device-only plugin → audience kind has no validator
    )
    with pytest.raises(CapAuthError) as exc:
        await r(_FakeRequest("GET", _URL, _redeem_headers(cert, anyone)))
    assert exc.value.status == 401


@pytest.mark.asyncio
async def test_writer_audience_cap_authorizes_json_post() -> None:
    from starfish_sharing import AudienceMintOpts

    writer = _make_key(0x71)
    cert = mint_audience_cap(
        ISSUER.ed_priv_hex,
        ISSUER.ed_pub_hex,
        "broadcast",
        scopes.writer("broadcast"),
        AudienceMintOpts(audience=[writer.ed_pub_hex], nbf=_now() - 10, ttl_sec=3600),
    )
    url = "https://api.example.com/push/broadcast/post-1"
    parts = urlsplit(url)
    body = json.dumps({"hello": "world"}).encode("utf-8")
    sig = sign_request("POST", parts.path, body, writer.ed_priv_hex, host=parts.netloc)
    headers = {
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
        "X-Starfish-Pub": writer.ed_pub_hex,
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }

    class _PostRequest(_FakeRequest):
        async def body(self) -> bytes:
            return body

    auth = await _resolver()(_PostRequest("POST", url, headers))
    assert auth.identity == user_id_from_pub_hex(writer.ed_pub_hex)
    assert "cap:write:broadcast" in auth.roles


@pytest.mark.asyncio
async def test_member_cap_authorizes_with_pub_header_present() -> None:
    # Forward-compat: a member cap verifies against cert["sub"]; a bogus
    # X-Starfish-Pub header must be ignored, not break the request.
    bob = _make_key(0x55)
    cert = mint_member_cap(
        ISSUER.ed_priv_hex,
        ISSUER.ed_pub_hex,
        {"edPubHex": bob.ed_pub_hex, "kemPubHex": "ee" * 32, "userIdHex": bob.user_id},
        "broadcast",
        scopes.read_only("broadcast"),
    )
    headers = _redeem_headers(cert, bob)
    headers["X-Starfish-Pub"] = "cc" * 32
    auth = await _resolver()(_FakeRequest("GET", _URL, headers))
    assert auth.identity == bob.user_id


@pytest.mark.asyncio
async def test_expired_audience_cap_rejected_401() -> None:
    from starfish_sharing import AudienceMintOpts

    cert = mint_audience_cap(
        ISSUER.ed_priv_hex,
        ISSUER.ed_pub_hex,
        "broadcast",
        scopes.read_only("broadcast"),
        AudienceMintOpts(nbf=_now() - 4000, ttl_sec=1000),
    )
    anyone = _make_key(0x71)
    with pytest.raises(CapAuthError) as exc:
        await _resolver()(_FakeRequest("GET", _URL, _redeem_headers(cert, anyone)))
    assert exc.value.status == 401
