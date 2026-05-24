"""Tests for device cap-cert minting helpers."""

import base64

from starfish_protocol.cap import verify_cap_cert
from starfish_identities.cap_mint import MintOpts, mint_device_cap, scopes
from starfish_identities.identity import derive_root_identity


def test_mint_device_cap_returns_verifying_cert() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub},
        scopes.root_all(),
    )
    assert cert["kind"] == "device"
    assert cert["iss"] == alice.keys.ed_pub
    assert cert["issUserId"] == alice.user_id
    assert cert["sub"] == bob.keys.ed_pub
    assert cert["subKem"] == bob.keys.kem_pub
    result = verify_cap_cert(cert, now=cert["nbf"] + 5)
    assert result["ok"] is True


def test_mint_device_cap_uses_ttl_sec() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub},
        scopes.root_all(),
        MintOpts(nbf=1_700_000_000, ttl_sec=60),
    )
    assert cert["nbf"] == 1_700_000_000
    assert cert["exp"] == 1_700_000_060


def test_mint_device_cap_injects_known_nonce() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    known = bytes(range(16))  # 0x00..0x0f
    expected = base64.b64encode(known).decode("ascii")
    cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub},
        scopes.root_all(),
        MintOpts(nonce=known),
    )
    assert cert["nonce"] == expected


def test_mint_device_cap_allows_secp256k1_kem_now_wrappable() -> None:
    # The KEM phase relaxed the old mint gate: a non-ed25519 sub_kem_alg is now
    # mintable (the keyring wraps under any suite's ECDH).
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub},
        scopes.root_all(),
        MintOpts(sub_kem_alg="secp256k1-schnorr"),
    )
    assert cert["subKemAlg"] == "secp256k1-schnorr"
    assert isinstance(cert["subKem"], str)
    assert verify_cap_cert(cert, now=cert["nbf"] + 5)["ok"] is True


def test_mint_device_cap_allows_secp256k1_sign_with_x25519_kem() -> None:
    # The one usable decoupled combo today (key bytes are stand-ins).
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub},
        scopes.root_all(),
        MintOpts(sub_alg="secp256k1-schnorr", sub_kem_alg="ed25519"),
    )
    assert cert["subAlg"] == "secp256k1-schnorr"
    assert cert["subKemAlg"] == "ed25519"
    assert isinstance(cert["subKem"], str)


def test_scopes_root_all() -> None:
    s = scopes.root_all()
    assert s["collections"] == ["*"]
    assert s["paths"] == ["**"]
