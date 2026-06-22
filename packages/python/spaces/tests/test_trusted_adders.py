"""Tests for compute_owner_trusted_adders (in starfish_identities)."""

from starfish_identities.trusted_adders import compute_owner_trusted_adders

OWNER_PUB = "a" * 64
SELF_PUB = "b" * 64


def test_different_owner_and_self():
    result = compute_owner_trusted_adders(OWNER_PUB, SELF_PUB)
    assert OWNER_PUB in result
    assert SELF_PUB in result
    assert len(result) == 2


def test_same_owner_and_self():
    result = compute_owner_trusted_adders(SELF_PUB, SELF_PUB)
    assert result == [SELF_PUB]


def test_none_owner_defaults_to_self():
    result = compute_owner_trusted_adders(None, SELF_PUB)
    assert result == [SELF_PUB]


def test_owner_comes_first():
    result = compute_owner_trusted_adders(OWNER_PUB, SELF_PUB)
    assert result[0] == OWNER_PUB
    assert result[1] == SELF_PUB
