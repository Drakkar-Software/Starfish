"""Cross-language vector tests for v3.0 root-identity derivation."""

import json
import pathlib
import re

import pytest

from starfish_identities.identity import (
    RootIdentity,
    RootKeyPair,
    derive_root_identity,
)

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent
    / "tests"
    / "test-vectors"
    / "identity-derivation.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text())

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")  # userId = sha256(edPub)[:32] (128-bit)


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["passphrase"])
def test_matches_cross_language_vectors(vector: dict) -> None:
    identity = derive_root_identity(vector["passphrase"])
    assert isinstance(identity, RootIdentity)
    assert isinstance(identity.keys, RootKeyPair)
    assert identity.keys.ed_priv == vector["rootEdPriv"]
    assert identity.keys.ed_pub == vector["rootEdPub"]
    assert identity.keys.kem_priv == vector["rootKemPriv"]
    assert identity.keys.kem_pub == vector["rootKemPub"]
    assert identity.user_id == vector["userId"]


def test_returns_64char_lowercase_hex_for_all_keys() -> None:
    identity = derive_root_identity("hello world")
    assert HEX64.match(identity.keys.ed_priv)
    assert HEX64.match(identity.keys.ed_pub)
    assert HEX64.match(identity.keys.kem_priv)
    assert HEX64.match(identity.keys.kem_pub)
    assert HEX32.match(identity.user_id)


def test_is_deterministic() -> None:
    a = derive_root_identity("a passphrase")
    b = derive_root_identity("a passphrase")
    assert a == b


def test_different_passphrases_yield_different_identities() -> None:
    a = derive_root_identity("passphrase one")
    b = derive_root_identity("passphrase two")
    assert a.keys.ed_priv != b.keys.ed_priv
    assert a.keys.kem_priv != b.keys.kem_priv
    assert a.user_id != b.user_id


def test_rejects_empty_passphrase() -> None:
    with pytest.raises(ValueError):
        derive_root_identity("")
    with pytest.raises(ValueError):
        derive_root_identity("   ")
