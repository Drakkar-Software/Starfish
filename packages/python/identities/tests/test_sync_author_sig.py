"""v3.0 author-signature plumbing — ``SyncManager`` with a ``signer``.

When a ``signer`` is configured, push payloads must carry:
- ``authorPubkey``: the dev Ed25519 pub (hex)
- ``authorSignature``: base64 Ed25519 over ``stable_stringify(payload-without-author-fields)``

The signature is over the canonical stringification of the entire encrypted
payload (e.g. ``{_encrypted, _epoch}``), *not* the plaintext.
"""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from starfish_protocol.hash import stable_stringify
from starfish_protocol.types import PullResult, PushSuccess
from starfish_identities.identity import derive_root_identity
from starfish_keyring import create_keyring, create_keyring_encryptor
from starfish_sdk.sync import SyncManager, SyncSigner


def _make_mock_client() -> MagicMock:
    client = MagicMock()
    client.pull = AsyncMock(return_value=PullResult(data={}, hash="h", timestamp=1))
    client.push = AsyncMock(return_value=PushSuccess(hash="h2", timestamp=2))
    return client


def _make_signer(dev_ed_priv_hex: str, dev_ed_pub_hex: str) -> SyncSigner:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(dev_ed_priv_hex))

    async def get_signer():
        async def sign(payload: bytes) -> bytes:
            return priv.sign(payload)

        return {"dev_ed_pub_hex": dev_ed_pub_hex, "sign": sign}

    signer = MagicMock()
    signer.get_signer = get_signer
    return signer  # type: ignore[return-value]


@pytest.mark.asyncio
async def test_push_attaches_author_pubkey_and_signature_to_encrypted_payload():
    alice = derive_root_identity("alice-root-passphrase")
    laptop = derive_root_identity("alice-laptop")
    keyring, _ = create_keyring(
        adder_ed_priv_hex=alice.keys.ed_priv,
        adder_ed_pub_hex=alice.keys.ed_pub,
        recipients=[laptop.keys.kem_pub],
    )
    encryptor = create_keyring_encryptor(
        keyring,
        recipient_kem_pub_hex=laptop.keys.kem_pub,
        recipient_kem_priv_hex=laptop.keys.kem_priv,
        trusted_adders=[alice.keys.ed_pub],
    )

    client = _make_mock_client()
    signer = _make_signer(laptop.keys.ed_priv, laptop.keys.ed_pub)

    sync = SyncManager(
        client,
        pull_path="/pull/test",
        push_path="/push/test",
        encryptor=encryptor,
        signer=signer,
    )
    await sync.push({"secret": "x"})

    assert client.push.await_count == 1
    args, kwargs = client.push.call_args
    # Signature: push(path, payload, base_hash)
    # In the v3 signer path, `payload` carries `authorPubkey` + `authorSignature`
    # inside the encrypted document.
    payload = args[1]

    assert "_encrypted" in payload
    assert "_epoch" in payload
    assert payload["authorPubkey"] == laptop.keys.ed_pub
    author_signature = payload["authorSignature"]
    assert isinstance(author_signature, str) and len(author_signature) > 0

    # Independently verify: the canonical signing input is stable_stringify of
    # the payload object without author fields.
    signed_payload = {k: v for k, v in payload.items() if k not in ("authorPubkey", "authorSignature")}
    canon = stable_stringify(signed_payload).encode("utf-8")
    sig_bytes = base64.b64decode(author_signature)
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(laptop.keys.ed_pub))
    # Throws InvalidSignature on failure
    pub.verify(sig_bytes, canon)


@pytest.mark.asyncio
async def test_push_without_signer_omits_author_fields():
    client = _make_mock_client()
    sync = SyncManager(client, pull_path="/pull/test", push_path="/push/test")
    await sync.push({"a": 1})

    assert client.push.await_count == 1
    args, _ = client.push.call_args
    payload = args[1]
    assert "authorPubkey" not in payload
    assert "authorSignature" not in payload
    # push() takes (path, payload, base_hash) — no author-signature slot.
    assert len(args) == 3
