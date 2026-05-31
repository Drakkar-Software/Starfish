"""Cross-language vector + behavior tests for ``derive_root_identity_from_evm_signature``.

Mirrors ``packages/ts/identities/tests/bootstrap-evm.test.ts`` so the TS and
Python implementations cannot drift on the EVM bootstrap derivation.

The vector's signatures are produced by a real EVM signer (``eth-account``,
EIP-191 ``personal_sign``, deterministic RFC 6979 ECDSA). One test re-signs with
``eth-account`` to prove the bytes a live wallet emits match the locked vector;
the rest assert against the vector alone so the suite runs without re-signing.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from starfish_identities.identity import (
    EVM_BOOTSTRAP_CHALLENGE,
    derive_root_identity,
    derive_root_identity_from_evm_signature,
)
from starfish_identities import mint_device_cap, scopes
from starfish_protocol import verify_cap_cert

_VECTOR_PATH = (
    pathlib.Path(__file__).resolve().parents[4]
    / "tests"
    / "test-vectors"
    / "identity-derivation-evm.json"
)
_VECTOR = json.loads(_VECTOR_PATH.read_text())
_CASES = _VECTOR["cases"]


def _sig(case: dict) -> bytes:
    return bytes.fromhex(case["signatureHex"].removeprefix("0x"))


def test_default_challenge_matches_vector() -> None:
    assert EVM_BOOTSTRAP_CHALLENGE == _VECTOR["defaultChallenge"]


# 2. Known-answer vector (locks cross-language agreement).
@pytest.mark.parametrize("case", _CASES, ids=[c["label"] for c in _CASES])
def test_locked_vector_case(case: dict) -> None:
    identity = derive_root_identity_from_evm_signature(
        case["address"], _sig(case), challenge=case["challenge"]
    )
    assert identity.keys.ed_priv == case["edPrivHex"]
    assert identity.keys.ed_pub == case["edPubHex"]
    assert identity.keys.kem_priv == case["kemPrivHex"]
    assert identity.keys.kem_pub == case["kemPubHex"]
    assert identity.user_id == case["userId"]
    assert identity.bootstrap_origin is not None
    assert identity.bootstrap_origin.kind == case["bootstrapOrigin"]["kind"]
    assert identity.bootstrap_origin.address == case["bootstrapOrigin"]["address"]


# A live EVM wallet's deterministic signature equals the locked vector bytes,
# and derives the same identity — proving the vector reflects real signers.
@pytest.mark.parametrize("case", _CASES, ids=[c["label"] for c in _CASES])
def test_live_signer_matches_vector(case: dict) -> None:
    signed = Account.sign_message(
        encode_defunct(case["challenge"].encode("utf-8")),
        private_key=case["privHex"],
    )
    assert bytes(signed.signature) == _sig(case)
    identity = derive_root_identity_from_evm_signature(
        case["address"], bytes(signed.signature), challenge=case["challenge"]
    )
    assert identity.user_id == case["userId"]


# Custom challenge namespaces identities: same wallet, different challenge → different identity.
def test_custom_challenge_yields_distinct_identity() -> None:
    default_case = next(c for c in _CASES if c["challenge"] == EVM_BOOTSTRAP_CHALLENGE)
    custom_case = next(c for c in _CASES if c["label"] == "fixture-evm-custom-challenge")
    assert default_case["address"] == custom_case["address"]  # same wallet
    default_id = derive_root_identity_from_evm_signature(
        default_case["address"], _sig(default_case)
    )
    custom_id = derive_root_identity_from_evm_signature(
        custom_case["address"], _sig(custom_case), challenge=custom_case["challenge"]
    )
    assert custom_id.user_id != default_id.user_id


# A signature over challenge A, derived with challenge B, recovers a different
# address → rejected by the address bind. This is what enforces challenge agreement.
def test_rejects_signature_under_a_different_challenge() -> None:
    c = next(c for c in _CASES if c["challenge"] == EVM_BOOTSTRAP_CHALLENGE)
    with pytest.raises(ValueError, match="does not recover to address"):
        derive_root_identity_from_evm_signature(
            c["address"], _sig(c), challenge="some-other-challenge"
        )


# 1. Determinism / stability — same input twice → identical identity.
def test_determinism_same_input_same_identity() -> None:
    c = _CASES[0]
    a = derive_root_identity_from_evm_signature(c["address"], _sig(c))
    b = derive_root_identity_from_evm_signature(c["address"], _sig(c))
    assert a.user_id == b.user_id
    assert a.keys.ed_priv == b.keys.ed_priv
    assert a.keys.ed_pub == b.keys.ed_pub
    assert a.keys.kem_priv == b.keys.kem_priv
    assert a.keys.kem_pub == b.keys.kem_pub


# 3. Verification rejects a valid signature presented with the wrong address.
def test_rejects_valid_signature_with_wrong_address() -> None:
    a, b = _CASES[0], _CASES[1]
    with pytest.raises(ValueError, match="does not recover to address"):
        derive_root_identity_from_evm_signature(b["address"], _sig(a))


# 4. Verification rejects a tampered signature.
def test_rejects_tampered_signature() -> None:
    c = _CASES[0]
    sig = bytearray(_sig(c))
    sig[0] ^= 0xFF  # flip a byte in r
    with pytest.raises(ValueError):
        derive_root_identity_from_evm_signature(c["address"], bytes(sig))


# 5. Malformed input — bad signature length.
def test_rejects_64_byte_signature() -> None:
    c = _CASES[0]
    with pytest.raises(ValueError, match="65 bytes"):
        derive_root_identity_from_evm_signature(c["address"], _sig(c)[:64])


def test_rejects_66_byte_signature() -> None:
    c = _CASES[0]
    with pytest.raises(ValueError, match="65 bytes"):
        derive_root_identity_from_evm_signature(c["address"], _sig(c) + b"\x00")


# 5. Malformed input — bad address.
def test_rejects_non_hex_address() -> None:
    c = _CASES[0]
    with pytest.raises(ValueError, match="EVM address"):
        derive_root_identity_from_evm_signature("0x" + "zz" * 20, _sig(c))


def test_rejects_address_without_0x_prefix() -> None:
    c = _CASES[0]
    with pytest.raises(ValueError, match="EVM address"):
        derive_root_identity_from_evm_signature(c["address"][2:], _sig(c))


def test_rejects_too_short_address() -> None:
    c = _CASES[0]
    with pytest.raises(ValueError, match="EVM address"):
        derive_root_identity_from_evm_signature(c["address"][:-2], _sig(c))


# 6. ed/kem seed separation — the two HKDF infos must produce distinct keys.
def test_ed_and_kem_seeds_differ() -> None:
    c = _CASES[0]
    identity = derive_root_identity_from_evm_signature(c["address"], _sig(c))
    assert identity.keys.ed_priv != identity.keys.kem_priv
    assert identity.keys.ed_pub != identity.keys.kem_pub


# 7. bootstrap_origin recorded; address comparison is case-insensitive.
def test_bootstrap_origin_recorded_and_case_insensitive() -> None:
    c = _CASES[0]
    identity = derive_root_identity_from_evm_signature(c["address"].lower(), _sig(c))
    assert identity.bootstrap_origin is not None
    assert identity.bootstrap_origin.kind == "evm"
    # The address stored is exactly what the caller passed in.
    assert identity.bootstrap_origin.address == c["address"].lower()
    # secp pub_hex stays unset on an EVM-origin identity.
    assert identity.bootstrap_origin.pub_hex is None


def test_bootstrap_origin_is_none_for_passphrase_derived_identities() -> None:
    identity = derive_root_identity("alice-root-passphrase")
    assert identity.bootstrap_origin is None


# 8. The derived identity is usable end-to-end: it mints a verifiable device cap.
def test_derived_identity_mints_verifiable_device_cap() -> None:
    c = _CASES[0]
    root = derive_root_identity_from_evm_signature(c["address"], _sig(c))
    cap = mint_device_cap(
        root.keys.ed_priv,
        root.keys.ed_pub,
        {"edPubHex": root.keys.ed_pub, "kemPubHex": root.keys.kem_pub},
        scopes.root_all(),
    )
    assert cap["kind"] == "device"
    assert cap["issUserId"] == root.user_id
    # Round-trips into the protocol verifier the server uses.
    assert verify_cap_cert(cap, now=cap["nbf"] + 5)["ok"] is True


# 9. Distinct EVM keys → distinct identities (no constant/collision bug).
def test_distinct_keys_distinct_identities() -> None:
    a = derive_root_identity_from_evm_signature(_CASES[0]["address"], _sig(_CASES[0]))
    b = derive_root_identity_from_evm_signature(_CASES[1]["address"], _sig(_CASES[1]))
    assert a.user_id != b.user_id
    assert a.keys.ed_pub != b.keys.ed_pub
