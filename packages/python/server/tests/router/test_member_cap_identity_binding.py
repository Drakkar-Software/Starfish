"""Member cap ``{identity}`` URL binding — Python mirror of
member-cap-identity-binding.test.ts.

A member cap from Alice to Bob sets ``auth.identity = bobUserId``. The
route guard then requires ``params.identity == auth.identity``, so Bob's
member cap can never reach Alice's private namespace.
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
from starfish_sharing import sharing_server_plugin
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


def _mint_member(
    iss: _Root,
    sub: _Root,
    collections: list[str],
    paths: list[str],
    ops: list[str] | None = None,
    nonce_seed: int = 7,
) -> dict:
    nbf = int(time.time()) - 10
    unsigned = {
        "v": 1,
        "kind": "member",
        "iss": iss.ed_pub_hex,
        "issUserId": iss.user_id,
        "sub": sub.ed_pub_hex,
        "subKem": sub.kem_pub_hex,
        "subUserId": sub.user_id,
        "scope": {
            "ops": ops or ["read", "list", "write"],
            "collections": collections,
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
                name="shared-team",
                storagePath="shared-team/{identity}/notes",
                readRoles=["cap:read:shared-team", "self"],
                writeRoles=["cap:write:shared-team", "self"],
                encryption="none",
                maxBodyBytes=1_000_000,
                allowedMimeTypes=["application/json"],
            ),
            CollectionConfig(
                name="private-notes",
                storagePath="users/{identity}/private-notes",
                readRoles=["self"],
                writeRoles=["self"],
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
        # Accept ``member`` caps: the resolver is device-only by default, so
        # the member-cap shape validator must be wired for these binding tests.
        plugins=[sharing_server_plugin],
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
async def test_member_cap_lets_subject_access_own_identity_slot() -> None:
    alice = _make_root(0xA1)
    bob = _make_root(0xA2)
    cert = _mint_member(
        alice,
        bob,
        collections=["shared-team"],
        paths=["shared-team/{identity}/notes"],
    )
    app, _ = _build_app()
    path = f"/pull/shared-team/{bob.user_id}/notes"
    headers = _signed_headers("GET", path, b"", bob.ed_priv_hex, _cap_header(cert))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(path, headers=headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_member_cap_cannot_reach_issuer_private_namespace() -> None:
    alice = _make_root(0xB1)
    bob = _make_root(0xB2)
    cert = _mint_member(
        alice,
        bob,
        collections=["shared-team"],
        paths=["shared-team/{identity}/notes"],
    )
    app, _ = _build_app()
    # Attempt to read alice's private-notes (params.identity = alice.user_id)
    # with bob's member cap (auth.identity = bob.user_id).
    path = f"/pull/users/{alice.user_id}/private-notes"
    headers = _signed_headers("GET", path, b"", bob.ed_priv_hex, _cap_header(cert))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(path, headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_member_cap_cannot_pose_as_issuer_in_shared_path() -> None:
    alice = _make_root(0xC1)
    bob = _make_root(0xC2)
    cert = _mint_member(
        alice,
        bob,
        collections=["shared-team"],
        paths=["shared-team/{identity}/notes"],
    )
    app, _ = _build_app()
    # Request targets alice's slot of shared-team. Bob's cap has
    # auth.identity = bob.user_id, so the identity binding rejects.
    path = f"/pull/shared-team/{alice.user_id}/notes"
    headers = _signed_headers("GET", path, b"", bob.ed_priv_hex, _cap_header(cert))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(path, headers=headers)
    assert resp.status_code == 403
