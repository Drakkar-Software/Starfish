"""End-to-end pipeline test for the Starfish v3 stack.

Mirrors ``packages/ts/server/tests/e2e/full-pipeline.test.ts`` in Python:

    bootstrap_root_identity  (alice — passphrase → root + self-signed device cap)
    ↓
    StarfishClient(cap_provider)  (signs every request with cap + Ed25519 sig)
    ↓
    create_sync_router + create_cap_cert_role_resolver
    ↓
    create_keyring_encryptor  (HPKE-DHKEM wrap → AES-GCM)
    ↓
    round-trip: push encrypted → pull encrypted → decrypt
    ↓
    pair Bob via mint_device_cap + add_recipient → Bob pushes → Alice pulls

Goal: lock the integration. Per-layer correctness lives in the unit tests.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi import FastAPI

from starfish_protocol.hash import stable_stringify
from starfish_sdk import StarfishClient, SyncManager
from starfish_sdk.types import StarfishHttpError
from starfish_sharing import create_public_link, parse_public_link, scopes
from starfish_keyring import (
    add_recipient as keyring_add_recipient,
    create_keyring,
    create_keyring_encryptor,
)
from starfish_identities import bootstrap_root_identity, mint_device_cap
from starfish_server.auth.nonce_cache import create_in_memory_nonce_cache
from starfish_server.auth.revocation_store import create_in_memory_revocation_store
from starfish_server.config.schema import CollectionConfig, SyncConfig
from starfish_server.router.cap_resolver import create_cap_cert_role_resolver
from starfish_server.router.route_builder import (
    SyncRouterOptions,
    create_sync_router,
)
from starfish_identities.plugin import identities_server_plugin
from starfish_sharing.plugin import sharing_server_plugin
from tests.helpers import MemoryObjectStore


def _make_config() -> SyncConfig:
    """Dual-collection layout — encrypted ``notes`` + plaintext keyring sibling.

    Mirrors ``with-keyring.test.ts`` so the encrypted collection rejects
    plaintext bodies while the keyring stays readable on the server.
    """
    return SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="notes",
                storagePath="users/{identity}/notes/{doc}",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="delegated",
                maxBodyBytes=1_000_000,
                allowedMimeTypes=["application/json"],
            ),
            CollectionConfig(
                name="notes_keyring",
                storagePath="users/{identity}/notes/_keyring",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=1_000_000,
                allowedMimeTypes=["application/json"],
            ),
            # Plaintext public-link collection (audience caps). The resolver's
            # `aud` membership check runs before role evaluation, so a non-listed
            # identity never reaches these role gates.
            CollectionConfig(
                name="broadcast",
                storagePath="broadcast/{doc}",
                readRoles=["cap:read:broadcast"],
                writeRoles=["cap:write:broadcast"],
                encryption="none",
                maxBodyBytes=1_000_000,
                allowedMimeTypes=["application/json"],
            ),
        ],
    )


def _make_server() -> tuple[FastAPI, MemoryObjectStore]:
    """Spin up FastAPI + real cap-cert resolver (no fakes).

    ``allow_anonymous=False`` forces every request through cap verification.
    """
    store = MemoryObjectStore()
    resolver = create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        allow_anonymous=False,
        # Compose the real extension plugins so the resolver dispatches per
        # cap kind through them (strict-kind dispatch on by default) — exercises
        # the plugin architecture end-to-end, not the legacy inline path.
        plugins=[identities_server_plugin, sharing_server_plugin],
    )
    router = create_sync_router(
        SyncRouterOptions(store=store, config=_make_config(), role_resolver=resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


class _CapProvider:
    """``StarfishCapProvider`` over a fixed cap + device priv key.

    ``pub_hex`` is supplied only for audience (public-link) caps, where the
    server needs the presenter's pubkey via ``X-Starfish-Pub``.
    """

    def __init__(
        self, cap: dict[str, Any], dev_ed_priv_hex: str, pub_hex: str | None = None
    ) -> None:
        self._cap = cap
        self._dev = dev_ed_priv_hex
        self._pub_hex = pub_hex

    async def get_cap(self) -> dict[str, Any]:
        ctx: dict[str, Any] = {"cap": self._cap, "dev_ed_priv_hex": self._dev}
        if self._pub_hex is not None:
            ctx["pub_hex"] = self._pub_hex
        return ctx


class _Signer:
    """``SyncSigner`` over the same Ed25519 device key as the cap provider."""

    def __init__(self, dev_ed_pub_hex: str, dev_ed_priv_hex: str) -> None:
        self._pub = dev_ed_pub_hex
        priv_bytes = bytes.fromhex(dev_ed_priv_hex)
        self._priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)

    async def get_signer(self) -> dict[str, Any]:
        async def sign(payload: bytes) -> bytes:
            return self._priv.sign(payload)

        return {"dev_ed_pub_hex": self._pub, "sign": sign}


def _make_test_client(
    app: FastAPI, cap: dict[str, Any], dev_ed_priv_hex: str, pub_hex: str | None = None
) -> tuple[StarfishClient, httpx.AsyncClient]:
    """Build a ``StarfishClient`` whose transport is an in-process ASGI app.

    Returns the SDK client and the underlying ``httpx.AsyncClient`` so the
    caller can ``aclose()`` it after the test. ``pub_hex`` is passed through for
    audience (public-link) redemption.
    """
    httpx_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://api.test",
    )
    sdk = StarfishClient(
        base_url="http://api.test",
        cap_provider=_CapProvider(cap, dev_ed_priv_hex, pub_hex),
        client=httpx_client,
    )
    return sdk, httpx_client


@pytest.mark.asyncio
async def test_alice_round_trip() -> None:
    """Alice bootstraps, publishes a keyring, encrypts, pushes, pulls, decrypts."""
    app, store = _make_server()

    # 1. Alice bootstraps. The default cap from bootstrap uses
    #    ``scopes.root_all()`` (``paths: ["*"]``), and ``*`` does not span
    #    slashes — so we re-mint Alice's cap with ``**`` to cover her
    #    ``users/<userId>/notes/...`` storage URLs.
    boot = bootstrap_root_identity("alice-pass")
    cap = mint_device_cap(
        boot.device["edPriv"],
        boot.device["edPub"],
        {"edPubHex": boot.device["edPub"], "kemPubHex": boot.device["kemPub"]},
        {
            "ops": ["read", "write", "list"],
            "collections": ["*"],
            "paths": ["**"],
        },
    )
    assert cap["sub"] == boot.device["edPub"]
    assert cap["iss"] == boot.root_ed_pub

    # 2. Build the in-memory keyring with Alice as the only recipient.
    keyring, _cek = create_keyring(
        adder_ed_priv_hex=boot.device["edPriv"],
        adder_ed_pub_hex=boot.device["edPub"],
        recipients=[boot.device["kemPub"]],
    )

    sdk, httpx_client = _make_test_client(app, cap, boot.device["edPriv"])
    try:
        # 3. Push the keyring document.
        keyring_path = f"users/{boot.user_id}/notes/_keyring"
        push_res = await sdk.push(
            f"/push/{keyring_path}",
            {
                "v": keyring.v,
                "currentEpoch": keyring.current_epoch,
                "epochs": {
                    k: {
                        "wrappedKeys": [
                            {
                                "subKem": e.sub_kem,
                                "ephKem": e.eph_kem,
                                "ct": e.ct,
                                "addedBy": e.added_by,
                                "addedSig": e.added_sig,
                                "addedAt": e.added_at,
                            }
                            for e in v.wrapped_keys
                        ],
                        "createdAt": v.created_at,
                    }
                    for k, v in keyring.epochs.items()
                },
            },
            None,
        )
        assert len(push_res.hash) == 64

        # 4. Pull the keyring through the client to confirm the round-trip path.
        fetched = await sdk.pull(f"/pull/{keyring_path}")
        fetched_keyring = _coerce_keyring(fetched.data)

        # 5. Build the encryptor.
        encryptor = create_keyring_encryptor(
            fetched_keyring,
            recipient_kem_pub_hex=boot.device["kemPub"],
            recipient_kem_priv_hex=boot.device["kemPriv"],
            trusted_adders=[boot.device["edPub"]],
        )

        # 6. Push an encrypted note via SyncManager (exercises signer plumbing).
        data_path = f"users/{boot.user_id}/notes/note-a"
        signer = _Signer(boot.device["edPub"], boot.device["edPriv"])
        sync = SyncManager(
            sdk,
            f"/pull/{data_path}",
            f"/push/{data_path}",
            encryptor=encryptor,
            signer=signer,
        )
        plaintext = {"title": "first note", "body": "hello world"}
        await sync.push(plaintext)

        # Server-side: stored envelope is encrypted + signed.
        stored_json = await store.get_string(data_path)
        assert stored_json is not None
        stored = json.loads(stored_json)
        assert isinstance(stored["data"]["_encrypted"], str)
        assert stored["data"]["_epoch"] == fetched_keyring.current_epoch
        assert stored["data"]["authorPubkey"] == boot.device["edPub"]
        assert isinstance(stored["data"]["authorSignature"], str)
        # Plaintext title is not on the wire.
        assert "first note" not in stable_stringify(stored["data"])

        # 7. Pull through a fresh SyncManager — must decrypt back to plaintext.
        sync2 = SyncManager(
            sdk,
            f"/pull/{data_path}",
            f"/push/{data_path}",
            encryptor=encryptor,
        )
        result = await sync2.pull()
        for k, v in plaintext.items():
            assert result.data[k] == v
    finally:
        await httpx_client.aclose()


@pytest.mark.asyncio
async def test_bob_pairs_pushes_alice_pulls() -> None:
    """Alice mints Bob's cap, adds Bob to keyring; Bob writes; Alice reads."""
    app, store = _make_server()

    # Alice bootstraps + re-mints a `**` cap (see test_alice_round_trip).
    boot = bootstrap_root_identity("alice-pair-pass")
    alice_cap = mint_device_cap(
        boot.device["edPriv"],
        boot.device["edPub"],
        {"edPubHex": boot.device["edPub"], "kemPubHex": boot.device["kemPub"]},
        {
            "ops": ["read", "write", "list"],
            "collections": ["*"],
            "paths": ["**"],
        },
    )
    alice_sdk, alice_httpx = _make_test_client(app, alice_cap, boot.device["edPriv"])

    # Bob's device generates its own Ed25519 + X25519 keypair.
    bob_ed_priv = Ed25519PrivateKey.generate()
    bob_ed_pub_bytes = bob_ed_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    bob_ed_priv_bytes = bob_ed_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    bob_kem_priv = X25519PrivateKey.generate()
    bob_kem_pub_bytes = bob_kem_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    bob_kem_priv_bytes = bob_kem_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    bob_device = {
        "edPriv": bob_ed_priv_bytes.hex(),
        "edPub": bob_ed_pub_bytes.hex(),
        "kemPriv": bob_kem_priv_bytes.hex(),
        "kemPub": bob_kem_pub_bytes.hex(),
    }

    bob_cap = mint_device_cap(
        boot.device["edPriv"],
        boot.device["edPub"],
        {"edPubHex": bob_device["edPub"], "kemPubHex": bob_device["kemPub"]},
        {
            "ops": ["read", "write", "list"],
            "collections": ["notes", "notes_keyring"],
            "paths": [f"users/{boot.user_id}/notes/**"],
        },
    )
    assert bob_cap["sub"] == bob_device["edPub"]
    assert bob_cap["iss"] == boot.device["edPub"]
    assert bob_cap["issUserId"] == boot.user_id

    try:
        # ── Alice publishes the keyring containing just herself ──
        keyring_path = f"users/{boot.user_id}/notes/_keyring"
        keyring, cek = create_keyring(
            adder_ed_priv_hex=boot.device["edPriv"],
            adder_ed_pub_hex=boot.device["edPub"],
            recipients=[boot.device["kemPub"]],
        )
        push_res = await alice_sdk.push(
            f"/push/{keyring_path}",
            _keyring_to_wire(keyring),
            None,
        )

        # ── Alice adds Bob as a recipient in-memory and re-pushes ──
        next_keyring = keyring_add_recipient(
            keyring,
            adder_ed_priv_hex=boot.device["edPriv"],
            adder_ed_pub_hex=boot.device["edPub"],
            current_cek=cek,
            recipient_kem_hex=bob_device["kemPub"],
        )
        await alice_sdk.push(
            f"/push/{keyring_path}",
            _keyring_to_wire(next_keyring),
            push_res.hash,
        )

        # ── Bob writes an encrypted note ──
        bob_sdk, bob_httpx = _make_test_client(app, bob_cap, bob_device["edPriv"])
        try:
            bob_pulled = await bob_sdk.pull(f"/pull/{keyring_path}")
            bob_keyring = _coerce_keyring(bob_pulled.data)
            bob_enc = create_keyring_encryptor(
                bob_keyring,
                recipient_kem_pub_hex=bob_device["kemPub"],
                recipient_kem_priv_hex=bob_device["kemPriv"],
                trusted_adders=[boot.device["edPub"]],
            )
            note_path = f"users/{boot.user_id}/notes/from-bob"
            bob_sync = SyncManager(
                bob_sdk,
                f"/pull/{note_path}",
                f"/push/{note_path}",
                encryptor=bob_enc,
                signer=_Signer(bob_device["edPub"], bob_device["edPriv"]),
            )
            note = {"author": "bob", "body": "hi alice"}
            await bob_sync.push(note)

            # Server-side: stored envelope authored by Bob's device key.
            stored_json = await store.get_string(note_path)
            assert stored_json is not None
            stored = json.loads(stored_json)
            assert isinstance(stored["data"]["_encrypted"], str)
            assert stored["data"]["authorPubkey"] == bob_device["edPub"]
        finally:
            await bob_httpx.aclose()

        # ── Alice pulls + decrypts Bob's note ──
        alice_enc = create_keyring_encryptor(
            next_keyring,
            recipient_kem_pub_hex=boot.device["kemPub"],
            recipient_kem_priv_hex=boot.device["kemPriv"],
            trusted_adders=[boot.device["edPub"]],
        )
        alice_sync = SyncManager(
            alice_sdk,
            f"/pull/{note_path}",
            f"/push/{note_path}",
            encryptor=alice_enc,
        )
        result = await alice_sync.pull()
        for k, v in note.items():
            assert result.data[k] == v
    finally:
        await alice_httpx.aclose()


@pytest.mark.asyncio
async def test_public_link_audience_round_trip() -> None:
    """Alice mints a restricted writer link; Bob redeems and round-trips a
    plaintext doc through the real router; a non-listed identity is rejected 403."""
    app, store = _make_server()

    alice = bootstrap_root_identity("alice-link-pass")
    bob = bootstrap_root_identity("bob-link-pass")
    carol = bootstrap_root_identity("carol-link-pass")

    # Alice mints a writer public link restricted to Bob; she shares the fragment.
    link = create_public_link(
        alice.device["edPriv"],
        alice.device["edPub"],
        "broadcast",
        scopes.writer("broadcast"),
        allowed_identities=[bob.device["edPub"]],
    )
    parsed = parse_public_link(link.fragment)
    assert parsed.cap["kind"] == "audience"

    doc_path = "broadcast/post-1"

    # Bob redeems with his OWN key + pub_hex (→ X-Starfish-Pub) through a real client.
    bob_sdk, bob_httpx = _make_test_client(
        app, parsed.cap, bob.device["edPriv"], bob.device["edPub"]
    )
    try:
        pushed = await bob_sdk.push(f"/push/{doc_path}", {"hello": "from bob"}, None)
        assert len(pushed.hash) == 64
        pulled = await bob_sdk.pull(f"/pull/{doc_path}")
        assert pulled.data["hello"] == "from bob"
        stored = await store.get_string(doc_path)
        assert stored is not None and "from bob" in stored
    finally:
        await bob_httpx.aclose()

    # Carol holds the same link but is NOT in `aud` → 403 (her signature is valid
    # for her own key, but membership fails).
    carol_sdk, carol_httpx = _make_test_client(
        app, parsed.cap, carol.device["edPriv"], carol.device["edPub"]
    )
    try:
        with pytest.raises(StarfishHttpError) as exc:
            await carol_sdk.pull(f"/pull/{doc_path}")
        assert exc.value.status == 403
    finally:
        await carol_httpx.aclose()


def _keyring_to_wire(keyring: Any) -> dict[str, Any]:
    """Serialize an in-memory ``Keyring`` to its on-wire dict form."""
    return {
        "v": keyring.v,
        "currentEpoch": keyring.current_epoch,
        "epochs": {
            k: {
                "wrappedKeys": [
                    {
                        "subKem": e.sub_kem,
                        "ephKem": e.eph_kem,
                        "ct": e.ct,
                        "addedBy": e.added_by,
                        "addedSig": e.added_sig,
                        "addedAt": e.added_at,
                    }
                    for e in v.wrapped_keys
                ],
                "createdAt": v.created_at,
            }
            for k, v in keyring.epochs.items()
        },
    }


def _coerce_keyring(wire: dict[str, Any]) -> Any:
    """Rebuild a ``Keyring`` dataclass from a wire dict."""
    from starfish_keyring.keyring import Keyring, KeyringEpoch, WrappedKeyEntry

    return Keyring(
        v=int(wire["v"]),
        current_epoch=int(wire["currentEpoch"]),
        epochs={
            k: KeyringEpoch(
                wrapped_keys=[
                    WrappedKeyEntry(
                        sub_kem=e["subKem"],
                        eph_kem=e["ephKem"],
                        ct=e["ct"],
                        added_by=e["addedBy"],
                        added_sig=e["addedSig"],
                        added_at=int(e["addedAt"]),
                    )
                    for e in v.get("wrappedKeys", [])
                ],
                created_at=int(v.get("createdAt", 0)),
            )
            for k, v in wire["epochs"].items()
        },
    )
