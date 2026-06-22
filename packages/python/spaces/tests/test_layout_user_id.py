"""Tests for default_user_id_from_ed_pub (sha256 prefix derivation)."""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from starfish_spaces.layout import default_user_id_from_ed_pub

_VECTOR_PATH = (
    pathlib.Path(__file__).parents[4] / "tests" / "test-vectors" / "spaces-userid.json"
)

# Deterministic fixture: sha256 of 32 zero bytes → userId
_ED_PUB_HEX = "0" * 64  # 32 zero bytes as hex


async def test_user_id_is_32_hex_chars():
    user_id = await default_user_id_from_ed_pub(_ED_PUB_HEX)
    assert len(user_id) == 32
    assert all(c in "0123456789abcdef" for c in user_id)


async def test_user_id_matches_sha256_prefix():
    expected = hashlib.sha256(bytes.fromhex(_ED_PUB_HEX)).digest()[:16].hex()
    user_id = await default_user_id_from_ed_pub(_ED_PUB_HEX)
    assert user_id == expected


async def test_user_id_different_for_different_keys():
    id_a = await default_user_id_from_ed_pub("a" * 64)
    id_b = await default_user_id_from_ed_pub("b" * 64)
    assert id_a != id_b


@pytest.mark.skipif(not _VECTOR_PATH.exists(), reason="spaces-userid.json not yet generated")
async def test_userid_vector():
    data = json.loads(_VECTOR_PATH.read_text())
    for case in data.get("cases", []):
        result = await default_user_id_from_ed_pub(case["edPub"])
        assert result == case["userId"], f"userId mismatch for edPub {case['edPub']}"
