"""Authority inheritance — Python mirror of authority-inheritance.test.ts.

A ``kind: "device"`` cap inherits the issuer's authority. ``auth.identity``
is set to ``issUserId`` regardless of what path identity the request
targets. This is the cryptographic root of "device of A cannot access
B's data".

Exercises the ``{identity}`` URL binding and the ``scope.paths`` glob
in the cap-resolver.
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
from starfish_server.router.route_builder import (
    SyncRouterOptions,
    create_sync_router,
)
from tests.helpers import MemoryObjectStore


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


def _mint_device(
    iss: _Root,
    sub: _Root,
    paths: list[str],
    collections: list[str] | None = None,
    ops: list[str] | None = None,
    nonce_seed: int = 7,
) -> dict:
    nbf = int(time.time()) - 10
    unsigned = {
        "v": 1,
        "kind": "device",
        "issAlg": "ed25519",
        "iss": iss.ed_pub_hex,
        "issUserId": iss.user_id,
        "sub": sub.ed_pub_hex,
        "subKem": sub.kem_pub_hex,
        "scope": {
            "ops": ops or ["read", "list", "write"],
            "collections": collections or ["data"],
            "paths": paths,
        },
        "nbf": nbf,
        "exp": nbf + 3600,
        "nonce": base64.b64encode(bytes([nonce_seed]) * 16).decode("ascii"),
    }
    return sign_cap_cert(unsigned, iss.ed_priv_hex)


def _cap_header(cert: dict) -> str:
    return "Cap " + base64.b64encode(json.dumps(cert).encode("utf-8")).decode("ascii")


def _build_app() -> tuple[FastAPI, MemoryObjectStore]:
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="data",
                storagePath="users/{identity}/data",
                readRoles=["cap:read:data", "self"],
                writeRoles=["cap:write:data", "self"],
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
        SyncRouterOptions(store=store, config=config, role_resolver=resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


def _signed_headers(
    method: str,
    path_and_query: str,
    body: bytes,
    ed_priv_hex: str,
    cert_header: str,
) -> dict[str, str]:
    # AsyncClient is created with ``base_url="http://test"``, so the server-side
    # resolver extracts host ``test`` from the inbound request URL. The signed
    # canonical input MUST bind the same host or sig verify fails.
    sig = sign_request(method, path_and_query, body, ed_priv_hex, host="test")
    return {
        "Authorization": cert_header,
        "X-Starfish-Sig": sig.sig,
        "X-Starfish-Ts": str(sig.ts),
        "X-Starfish-Nonce": sig.nonce,
    }


@pytest.mark.asyncio
async def test_device_cap_can_pull_issuer_own_path() -> None:
    alice = _make_root(0x21)
    alice_dev = _make_root(0x22)
    cert = _mint_device(alice, alice_dev, ["users/*/data"])
    app, _ = _build_app()
    path = f"/pull/users/{alice.user_id}/data"
    headers = _signed_headers("GET", path, b"", alice_dev.ed_priv_hex, _cap_header(cert))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(path, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"] == {}


@pytest.mark.asyncio
async def test_device_cap_rejected_on_different_user_path() -> None:
    alice = _make_root(0x31)
    bob = _make_root(0x32)
    alice_dev = _make_root(0x33)
    cert = _mint_device(alice, alice_dev, ["users/*/data"])
    app, _ = _build_app()
    path = f"/pull/users/{bob.user_id}/data"
    headers = _signed_headers("GET", path, b"", alice_dev.ed_priv_hex, _cap_header(cert))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(path, headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_adversarial_scope_paths_cannot_override_identity_binding() -> None:
    # Even when the cap's scope.paths explicitly lists bob's namespace,
    # auth.identity is server-controlled (= issUserId for a device cap),
    # so the identity-vs-params check still rejects.
    alice = _make_root(0x41)
    bob = _make_root(0x42)
    alice_dev = _make_root(0x43)
    cert = _mint_device(alice, alice_dev, [f"users/{bob.user_id}/data"])
    app, _ = _build_app()
    path = f"/pull/users/{bob.user_id}/data"
    headers = _signed_headers("GET", path, b"", alice_dev.ed_priv_hex, _cap_header(cert))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(path, headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_device_cap_with_mismatched_scope_paths_rejected_even_on_own_identity() -> None:
    alice = _make_root(0x51)
    alice_dev = _make_root(0x52)
    cert = _mint_device(alice, alice_dev, ["notes/*"])
    app, _ = _build_app()
    path = f"/pull/users/{alice.user_id}/data"
    headers = _signed_headers("GET", path, b"", alice_dev.ed_priv_hex, _cap_header(cert))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(path, headers=headers)
    assert resp.status_code == 403
