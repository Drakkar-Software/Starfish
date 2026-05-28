"""Cross-language vector tests for ``derive_root_identity_from_secp256k1_signature``.

Mirrors ``packages/ts/identities/tests/bootstrap-secp256k1.test.ts`` exactly so
the TS and Python implementations cannot drift on the bootstrap derivation.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from starfish_identities.identity import (
    SECP256K1_BOOTSTRAP_CHALLENGE,
    derive_root_identity,
    derive_root_identity_from_secp256k1_signature,
)

_VECTOR_PATH = (
    pathlib.Path(__file__).resolve().parents[4]
    / "tests"
    / "test-vectors"
    / "identity-derivation-secp256k1.json"
)
_VECTOR = json.loads(_VECTOR_PATH.read_text())
_CASES = _VECTOR["cases"]


def test_bootstrap_challenge_equals_sha256_of_literal() -> None:
    literal = _VECTOR["challenge"]["literal"].encode("utf-8")
    expected = hashlib.sha256(literal).digest()
    assert expected.hex() == _VECTOR["challenge"]["challengeHex"]
    assert SECP256K1_BOOTSTRAP_CHALLENGE.hex() == _VECTOR["challenge"]["challengeHex"]


def test_bootstrap_challenge_is_32_bytes() -> None:
    assert len(SECP256K1_BOOTSTRAP_CHALLENGE) == 32


@pytest.mark.parametrize("case", _CASES, ids=[c["label"] for c in _CASES])
def test_locked_vector_case(case: dict) -> None:
    identity = derive_root_identity_from_secp256k1_signature(
        case["secpPubHex"],
        bytes.fromhex(case["signatureHex"]),
    )
    assert identity.keys.ed_priv == case["edPrivHex"]
    assert identity.keys.ed_pub == case["edPubHex"]
    assert identity.keys.kem_priv == case["kemPrivHex"]
    assert identity.keys.kem_pub == case["kemPubHex"]
    assert identity.user_id == case["userId"]
    assert identity.bootstrap_origin is not None
    assert identity.bootstrap_origin.kind == case["bootstrapOrigin"]["kind"]
    assert identity.bootstrap_origin.pub_hex == case["bootstrapOrigin"]["pubHex"]


def test_determinism_same_input_same_identity() -> None:
    c = _CASES[0]
    a = derive_root_identity_from_secp256k1_signature(c["secpPubHex"], bytes.fromhex(c["signatureHex"]))
    b = derive_root_identity_from_secp256k1_signature(c["secpPubHex"], bytes.fromhex(c["signatureHex"]))
    assert a.user_id == b.user_id
    assert a.keys.ed_priv == b.keys.ed_priv
    assert a.keys.ed_pub == b.keys.ed_pub
    assert a.keys.kem_priv == b.keys.kem_priv
    assert a.keys.kem_pub == b.keys.kem_pub


def test_rejects_63_byte_signature() -> None:
    c = _CASES[0]
    with pytest.raises(ValueError, match="64 bytes"):
        derive_root_identity_from_secp256k1_signature(
            c["secpPubHex"], bytes.fromhex(c["signatureHex"])[:63]
        )


def test_rejects_65_byte_signature() -> None:
    c = _CASES[0]
    with pytest.raises(ValueError, match="64 bytes"):
        derive_root_identity_from_secp256k1_signature(
            c["secpPubHex"], bytes.fromhex(c["signatureHex"]) + b"\x00"
        )


def test_rejects_forged_all_zero_signature_against_valid_pubkey() -> None:
    c = _CASES[0]
    with pytest.raises(ValueError, match="does not verify"):
        derive_root_identity_from_secp256k1_signature(c["secpPubHex"], b"\x00" * 64)


def test_rejects_non_hex_secp_pub_hex() -> None:
    c = _CASES[0]
    with pytest.raises(ValueError, match="64 lowercase hex"):
        derive_root_identity_from_secp256k1_signature(
            "zz" * 32, bytes.fromhex(c["signatureHex"])
        )


def test_rejects_63_char_secp_pub_hex() -> None:
    c = _CASES[0]
    with pytest.raises(ValueError, match="64 lowercase hex"):
        derive_root_identity_from_secp256k1_signature(
            c["secpPubHex"][:63], bytes.fromhex(c["signatureHex"])
        )


def test_rejects_65_char_secp_pub_hex() -> None:
    c = _CASES[0]
    with pytest.raises(ValueError, match="64 lowercase hex"):
        derive_root_identity_from_secp256k1_signature(
            c["secpPubHex"] + "a", bytes.fromhex(c["signatureHex"])
        )


def test_rejects_uppercase_secp_pub_hex() -> None:
    c = _CASES[0]
    with pytest.raises(ValueError, match="64 lowercase hex"):
        derive_root_identity_from_secp256k1_signature(
            c["secpPubHex"].upper(), bytes.fromhex(c["signatureHex"])
        )


def test_rejects_trailing_newline_in_secp_pub_hex() -> None:
    # Python's regex `$` matches before a final `\n` and `re.match` doesn't
    # anchor at end, so `"<64-hex>\n"` passed older predicates that used
    # `_SECP_PUBHEX_RE.match`. TS rejects it via `/^[0-9a-f]{64}$/.test`. The
    # canonical fix here is `fullmatch`; this test locks the cross-lang behavior.
    c = _CASES[0]
    with pytest.raises(ValueError, match="64 lowercase hex"):
        derive_root_identity_from_secp256k1_signature(
            c["secpPubHex"] + "\n", bytes.fromhex(c["signatureHex"])
        )


def test_rejects_valid_signature_with_wrong_secp_pub_hex() -> None:
    # Binding check: case[0]'s signature does NOT verify against case[1]'s pubkey.
    a, b = _CASES[0], _CASES[1]
    with pytest.raises(ValueError, match="does not verify"):
        derive_root_identity_from_secp256k1_signature(
            b["secpPubHex"], bytes.fromhex(a["signatureHex"])
        )


def test_bootstrap_origin_is_set_for_bootstrapped_identities() -> None:
    c = _CASES[0]
    identity = derive_root_identity_from_secp256k1_signature(
        c["secpPubHex"], bytes.fromhex(c["signatureHex"])
    )
    assert identity.bootstrap_origin is not None
    assert identity.bootstrap_origin.kind == "secp256k1"
    assert identity.bootstrap_origin.pub_hex == c["secpPubHex"]


def test_bootstrap_origin_is_none_for_passphrase_derived_identities() -> None:
    identity = derive_root_identity("alice-root-passphrase")
    assert identity.bootstrap_origin is None
