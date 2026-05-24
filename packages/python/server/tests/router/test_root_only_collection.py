"""``rootOnly`` collections — Python mirror of root-only-collection.test.ts.

Only the root device (a self-signed device cap, ``iss == sub``) may access a
``rootOnly`` collection. Every paired/delegated device cap lacks
``ROLE_ROOT_DEVICE`` and is rejected with 403 — on standalone pull/list/push
AND on bundle pulls (the bundle handler shares ``_is_access_allowed`` with
``_check_auth``).
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
from starfish_server.router.route_builder import SyncRouterOptions, create_sync_router
from tests.helpers import MemoryObjectStore


@dataclass
class _Keys:
    ed_priv_hex: str
    ed_pub_hex: str
    user_id: str
    kem_pub_hex: str


def _make_keys(seed: int) -> _Keys:
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
    kem_priv = X25519PrivateKey.from_private_bytes(bytes([seed + 1]) * 32)
    kem_pub = kem_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _Keys(
        ed_priv_hex=priv_bytes.hex(),
        ed_pub_hex=pub_bytes.hex(),
        user_id=hashlib.sha256(pub_bytes).hexdigest()[:32],
        kem_pub_hex=kem_pub.hex(),
    )


def _mint_device(iss: _Keys, sub: _Keys, collections: list[str], nonce_seed: int) -> dict:
    nbf = int(time.time()) - 10
    unsigned = {
        "v": 1,
        "kind": "device",
        "issAlg": "ed25519",
        "iss": iss.ed_pub_hex,
        "issUserId": iss.user_id,
        "sub": sub.ed_pub_hex,
        "subKem": sub.kem_pub_hex,
        "scope": {"ops": ["read", "list", "write"], "collections": collections, "paths": ["**"]},
        "nbf": nbf,
        "exp": nbf + 3600,
        "nonce": base64.b64encode(bytes([nonce_seed]) * 16).decode("ascii"),
    }
    return sign_cap_cert(unsigned, iss.ed_priv_hex)


def _root_cert(root: _Keys, collections: list[str], nonce_seed: int = 0x10) -> dict:
    # Root device: self-signed cap (iss == sub).
    return _mint_device(root, root, collections, nonce_seed)


def _paired_cert(root: _Keys, device: _Keys, collections: list[str], nonce_seed: int = 0x20) -> dict:
    # Paired device: minted by the root for a separate keypair (iss != sub).
    return _mint_device(root, device, collections, nonce_seed)


def _cap_header(cert: dict) -> str:
    return "Cap " + base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")


def _col(name: str, storage_path: str, **over: object) -> CollectionConfig:
    return CollectionConfig(
        name=name,
        storagePath=storage_path,
        readRoles=[f"cap:read:{name}"],
        writeRoles=[f"cap:write:{name}"],
        encryption="none",
        maxBodyBytes=1_000_000,
        allowedMimeTypes=["application/json"],
        **over,
    )


def _build_app() -> FastAPI:
    config = SyncConfig(
        version=1,
        collections=[
            _col("secret", "secret/{slot}", rootOnly=True, listable=True),
            _col("open", "open/{slot}"),
            _col("pub", "room/{rid}", bundle="b"),
            _col("sec", "room/{rid}", bundle="b", rootOnly=True),
            _col("other", "room/{rid}", bundle="b"),
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


def _signed(method: str, path: str, body: bytes, ed_priv_hex: str, cert: dict) -> dict[str, str]:
    sig = sign_request(method, path, body, ed_priv_hex, host="test")
    headers = {
        "Authorization": _cap_header(cert),
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
    }
    if body:
        headers["content-type"] = "application/json"
    return headers


_PUSH_BODY = json.dumps({"data": {"v": 1}, "baseHash": None}).encode("utf-8")


@pytest.mark.asyncio
async def test_root_device_can_read_list_and_write_root_only() -> None:
    root = _make_keys(0x21)
    cert = _root_cert(root, ["secret"])
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        pull_path = "/pull/secret/s1"
        r = await client.get(pull_path, headers=_signed("GET", pull_path, b"", root.ed_priv_hex, cert))
        assert r.status_code == 200, r.text

        list_path = "/list/secret"
        r = await client.get(list_path, headers=_signed("GET", list_path, b"", root.ed_priv_hex, cert))
        assert r.status_code == 200, r.text

        push_path = "/push/secret/s1"
        r = await client.post(
            push_path,
            content=_PUSH_BODY,
            headers=_signed("POST", push_path, _PUSH_BODY, root.ed_priv_hex, cert),
        )
        assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_paired_device_denied_read_list_and_write_root_only() -> None:
    root = _make_keys(0x31)
    device = _make_keys(0x32)
    # Same scope.collections as the root cap, so the read/write role gate alone
    # would pass — only the rootOnly (ROLE_ROOT_DEVICE) gate rejects it.
    cert = _paired_cert(root, device, ["secret"])
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        pull_path = "/pull/secret/s1"
        r = await client.get(pull_path, headers=_signed("GET", pull_path, b"", device.ed_priv_hex, cert))
        assert r.status_code == 403

        list_path = "/list/secret"
        r = await client.get(list_path, headers=_signed("GET", list_path, b"", device.ed_priv_hex, cert))
        assert r.status_code == 403

        push_path = "/push/secret/s1"
        r = await client.post(
            push_path,
            content=_PUSH_BODY,
            headers=_signed("POST", push_path, _PUSH_BODY, device.ed_priv_hex, cert),
        )
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_anonymous_denied_root_only() -> None:
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get("/pull/secret/s1")
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_paired_device_still_reaches_non_root_only() -> None:
    root = _make_keys(0x41)
    device = _make_keys(0x42)
    cert = _paired_cert(root, device, ["open"])
    app = _build_app()
    path = "/pull/open/s1"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get(path, headers=_signed("GET", path, b"", device.ed_priv_hex, cert))
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_bundle_pull_omits_root_only_and_unauthorized_members_for_paired_device() -> None:
    root = _make_keys(0x51)
    device = _make_keys(0x52)
    # Holds roles for pub + sec (NOT other). sec is rootOnly, excluded by the
    # rootOnly gate; other is excluded by the read-role check.
    cert = _paired_cert(root, device, ["pub", "sec"])
    app = _build_app()
    path = "/pull/room/r1"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get(path, headers=_signed("GET", path, b"", device.ed_priv_hex, cert))
    assert r.status_code == 200, r.text
    assert sorted(r.json()["collections"].keys()) == ["pub"]


@pytest.mark.asyncio
async def test_bundle_pull_includes_root_only_member_for_root_device() -> None:
    root = _make_keys(0x61)
    cert = _root_cert(root, ["pub", "sec", "other"])
    app = _build_app()
    path = "/pull/room/r1"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r = await client.get(path, headers=_signed("GET", path, b"", root.ed_priv_hex, cert))
    assert r.status_code == 200, r.text
    assert sorted(r.json()["collections"].keys()) == ["other", "pub", "sec"]
