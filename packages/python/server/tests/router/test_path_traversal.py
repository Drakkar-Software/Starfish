"""Path-traversal guard on pull paths — Python mirror of path-traversal.test.ts.

``validate_path_segment`` only constrains a single param's charset and admits
``..``. The standalone JSON pull re-checks the resolved key inside
``handle_sync_pull``, but the binary ``get_bytes`` branch and the bundle-pull
loop read the store directly — so a non-``{identity}`` param carrying ``..``
would compose a traversal key that the cap scope ``col/**`` matches. Both paths
must reject an unsafe resolved key with 400.
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
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from starfish_protocol.cap import sign_cap_cert
from starfish_protocol.request_signing import sign_request
from starfish_server.auth.nonce_cache import create_in_memory_nonce_cache
from starfish_server.auth.revocation_store import create_in_memory_revocation_store
from starfish_server.config.schema import CollectionConfig, SyncConfig
from starfish_server.router.cap_resolver import create_cap_cert_role_resolver
from starfish_server.router.helpers import is_unsafe_document_key, validate_path_segment
from starfish_server.router.route_builder import SyncRouterOptions, create_sync_router
from tests.helpers import MemoryObjectStore

# `x..y` passes the per-segment charset check, reaches the handler (no router
# normalization, unlike a bare `..` segment), and composes a resolved key
# containing `..` — the sequence the guard must reject.
_TRAVERSAL = "x..y"


@dataclass
class _Keys:
    ed_priv_hex: str
    ed_pub_hex: str
    user_id: str
    kem_pub_hex: str


def _make_keys(seed: int) -> _Keys:
    priv = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    kem_priv = X25519PrivateKey.from_private_bytes(bytes([seed + 1]) * 32)
    kem_pub = kem_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return _Keys(
        ed_priv_hex=priv_bytes.hex(),
        ed_pub_hex=pub_bytes.hex(),
        user_id=hashlib.sha256(pub_bytes).hexdigest()[:32],
        kem_pub_hex=kem_pub.hex(),
    )


def _device_cert(k: _Keys, collections: list[str]) -> dict:
    nbf = int(time.time()) - 10
    unsigned = {
        "v": 1,
        "kind": "device",
        "issAlg": "ed25519",
        "iss": k.ed_pub_hex,
        "issUserId": k.user_id,
        "sub": k.ed_pub_hex,
        "subKem": k.kem_pub_hex,
        "scope": {"ops": ["read", "list", "write"], "collections": collections, "paths": ["**"]},
        "nbf": nbf,
        "exp": nbf + 3600,
        "nonce": base64.b64encode(bytes([0x55]) * 16).decode("ascii"),
    }
    return sign_cap_cert(unsigned, k.ed_priv_hex)


def _cap_header(cert: dict) -> str:
    return "Cap " + base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")


def _signed_get(path: str, k: _Keys, cert: dict) -> dict[str, str]:
    sig = sign_request("GET", path, b"", k.ed_priv_hex, host="test")
    return {
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
    }


def _build_app() -> FastAPI:
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="files",
                storagePath="files/{slot}",
                readRoles=["cap:read:files"],
                writeRoles=["cap:write:files"],
                encryption="none",
                maxBodyBytes=1_000_000,
                allowedMimeTypes=["application/octet-stream"],
            ),
            CollectionConfig(
                name="pub",
                storagePath="room/{rid}",
                bundle="b",
                readRoles=["cap:read:pub"],
                writeRoles=["cap:write:pub"],
                encryption="none",
                maxBodyBytes=1_000_000,
                allowedMimeTypes=["application/json"],
            ),
            CollectionConfig(
                name="other",
                storagePath="room/{rid}",
                bundle="b",
                readRoles=["cap:read:other"],
                writeRoles=["cap:write:other"],
                encryption="none",
                maxBodyBytes=1_000_000,
                allowedMimeTypes=["application/json"],
            ),
        ],
    )
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        allow_anonymous=True,
    )
    router = create_sync_router(
        SyncRouterOptions(store=MemoryObjectStore(), config=config, role_resolver=resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app


def test_is_unsafe_document_key() -> None:
    assert is_unsafe_document_key("files/../secret") is True
    assert is_unsafe_document_key("files/x..y") is True
    assert is_unsafe_document_key("a//b") is True
    assert is_unsafe_document_key("files/\x01") is True
    assert is_unsafe_document_key("files/s1") is False
    assert is_unsafe_document_key("room/r1") is False


def test_path_segment_rejects_trailing_newline() -> None:
    # The charset is [a-zA-Z0-9._:@-]; a newline is not in it. validate_path_segment
    # now uses re.fullmatch (not .match), so a trailing newline is rejected — Python's
    # `$` would otherwise match *before* it. Matches the TypeScript validatePathSegment
    # twin in path-traversal.test.ts. Same fix applied to the sibling `$`-anchor sites
    # (_NS_NAME_RE, _CAP_ROLE_RE, filesystem _VALID_KEY).
    assert validate_path_segment("alice\n") is False
    assert validate_path_segment("alice") is True


@pytest.mark.asyncio
async def test_binary_pull_rejects_traversal() -> None:
    k = _make_keys(0x61)
    cert = _device_cert(k, ["files"])
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        path = f"/pull/files/{_TRAVERSAL}"
        r = await client.get(path, headers=_signed_get(path, k, cert))
        assert r.status_code == 400, r.text


@pytest.mark.asyncio
async def test_binary_pull_clean_param_reaches_store() -> None:
    k = _make_keys(0x62)
    cert = _device_cert(k, ["files"])
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        path = "/pull/files/s1"
        r = await client.get(path, headers=_signed_get(path, k, cert))
        assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_bundle_pull_rejects_traversal() -> None:
    k = _make_keys(0x71)
    cert = _device_cert(k, ["pub", "other"])
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        path = f"/pull/room/{_TRAVERSAL}"
        r = await client.get(path, headers=_signed_get(path, k, cert))
        assert r.status_code == 400, r.text


@pytest.mark.asyncio
async def test_bundle_pull_clean_param_yields_bundle() -> None:
    k = _make_keys(0x72)
    cert = _device_cert(k, ["pub", "other"])
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        path = "/pull/room/r1"
        r = await client.get(path, headers=_signed_get(path, k, cert))
        assert r.status_code == 200, r.text
