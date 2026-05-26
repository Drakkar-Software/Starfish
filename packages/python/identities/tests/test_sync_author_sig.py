"""v3.0 document author-proof plumbing — ``SyncManager`` with a ``signer``.

When a ``signer`` is configured, the push carries the author proof as a 4th
argument to ``client.push`` (top-level body siblings of ``data``, NOT inside it):
- ``authorPubkey``: the dev Ed25519 pub (hex)
- ``authorSignature``: base64 Ed25519 over the doc-author canonical input —
  ``DOC_AUTHOR_DOMAIN + stable_stringify({"k": document_key, "d": sealed})``.

The signature is over the canonical form of the encrypted payload (e.g.
``{_encrypted, _epoch}``) bound to the document_key, *not* the plaintext.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from starfish_protocol.append_author import verify_doc_author
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
async def test_push_passes_verifiable_author_proof_as_4th_arg():
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
        pull_path="/pull/notes",
        push_path="/push/notes",
        encryptor=encryptor,
        signer=signer,
    )
    await sync.push({"secret": "x"})

    assert client.push.await_count == 1
    args, _ = client.push.call_args
    # push(path, payload, base_hash, author)
    payload = args[1]
    author = args[3]

    # The encrypted payload is sent as `data`, WITHOUT author fields (those are
    # now the top-level 4th arg).
    assert "_encrypted" in payload
    assert "_epoch" in payload
    assert "authorPubkey" not in payload
    assert "authorSignature" not in payload

    assert author is not None
    assert author["authorPubkey"] == laptop.keys.ed_pub
    # The proof verifies as a DOCUMENT author signature over the sealed payload,
    # bound to the document_key ("notes", derived from "/push/notes").
    assert verify_doc_author(
        "notes", payload, author["authorPubkey"], author["authorSignature"]
    ) is True
    # …and NOT under a different document_key (path binding).
    assert verify_doc_author(
        "other", payload, author["authorPubkey"], author["authorSignature"]
    ) is False


@pytest.mark.asyncio
async def test_push_without_signer_omits_author_proof():
    client = _make_mock_client()
    sync = SyncManager(client, pull_path="/pull/test", push_path="/push/test")
    await sync.push({"a": 1})

    assert client.push.await_count == 1
    args, _ = client.push.call_args
    payload = args[1]
    author = args[3]
    # No signer → author proof is None; `data` carries no author fields.
    assert author is None
    assert "authorPubkey" not in payload
    assert "authorSignature" not in payload
