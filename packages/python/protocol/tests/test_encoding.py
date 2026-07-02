"""Tests for starfish_protocol.encoding."""

import pytest

from starfish_protocol.encoding import (
    decode_link_fragment,
    encode_link_fragment,
    from_base64url,
    to_base64url,
)


# ── to_base64url ──────────────────────────────────────────────────────────────

def test_to_base64url_known_vector():
    assert to_base64url('{"type":"space","id":"abc"}') == "eyJ0eXBlIjoic3BhY2UiLCJpZCI6ImFiYyJ9"


def test_from_base64url_known_vector():
    assert from_base64url("eyJ0eXBlIjoic3BhY2UiLCJpZCI6ImFiYyJ9") == '{"type":"space","id":"abc"}'


# ── round-trips ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("s", [
    '{"type":"space","id":"abc"}',
    "hello world",
    "",
    "x" * 200,
    '{"nested":{"a":1},"arr":[1,2,3]}',
])
def test_round_trip(s: str):
    assert from_base64url(to_base64url(s)) == s


# ── URL-safety ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("s", [
    '{"type":"space","id":"abc"}',
    "hello world",
    "a" * 100,
    '{"a":1,"b":2,"c":3}',
])
def test_url_safe_no_forbidden_chars(s: str):
    encoded = to_base64url(s)
    assert "+" not in encoded
    assert "/" not in encoded
    assert "=" not in encoded


# ── padding cases (len % 3 ∈ {0,1,2}) ────────────────────────────────────────

def test_padding_mod0():
    # "abc" → 3 bytes → no padding needed
    s = "abc"
    assert from_base64url(to_base64url(s)) == s


def test_padding_mod1():
    # "ab" → 2 bytes → 2 padding chars would be needed in standard base64
    s = "ab"
    encoded = to_base64url(s)
    assert "=" not in encoded
    assert from_base64url(encoded) == s


def test_padding_mod2():
    # "a" → 1 byte → 1 padding char would be needed in standard base64
    s = "a"
    encoded = to_base64url(s)
    assert "=" not in encoded
    assert from_base64url(encoded) == s


# ── encode_link_fragment / decode_link_fragment round-trip ───────────────────

def _space_invite_validate(tok):
    # ``decode_link_fragment`` recovers the token (the 3rd array element) and
    # hands it here — matching the real spaces validators, which all expect the
    # token dict, and the base64url.json vector's "decode recovers the token".
    if not isinstance(tok, dict):
        return None
    if tok.get("type") != "space-invite":
        return None
    return tok


def test_link_fragment_round_trip():
    origin = "https://app.example.com"
    path = "/join"
    token = {"type": "space-invite", "id": "xyz123", "role": "writer"}

    url = encode_link_fragment(origin, path, token)
    assert url.startswith("https://app.example.com/join#")

    fragment = url.split("#", 1)[1]
    result = decode_link_fragment(fragment, _space_invite_validate)
    assert result == token


def test_link_fragment_emits_canonical_array_form():
    # The fragment is base64url(JSON([origin, path, token])) — byte-identical to
    # the TS encoder, so links are mutually decodable across languages.
    import json

    origin = "https://app.example.com"
    path = "/join"
    token = {"type": "space-invite", "id": "xyz123"}
    fragment = encode_link_fragment(origin, path, token).split("#", 1)[1]
    assert json.loads(from_base64url(fragment)) == [origin, path, token]


def test_link_fragment_matches_cross_language_vector():
    origin = "https://app.example.com"
    path = "/spaces/sp-abc"
    token = {"type": "space-invite", "id": "sp-abc", "expiresAt": 1900000000}
    expected_fragment = (
        "WyJodHRwczovL2FwcC5leGFtcGxlLmNvbSIsIi9zcGFjZXMvc3AtYWJjIix7InR5cGUiOiJz"
        "cGFjZS1pbnZpdGUiLCJpZCI6InNwLWFiYyIsImV4cGlyZXNBdCI6MTkwMDAwMDAwMH1d"
    )
    assert encode_link_fragment(origin, path, token).split("#", 1)[1] == expected_fragment


def test_decode_link_fragment_strips_hash_prefix():
    origin = "https://app.example.com"
    path = "/invite"
    token = {"type": "space-invite", "id": "abc"}

    url = encode_link_fragment(origin, path, token)
    fragment_with_hash = "#" + url.split("#", 1)[1]
    result = decode_link_fragment(fragment_with_hash, _space_invite_validate)
    assert result == token


def test_decode_link_fragment_raises_on_invalid():
    with pytest.raises(ValueError):
        decode_link_fragment("not-valid-base64url!!!", _space_invite_validate)


def test_decode_link_fragment_raises_on_none_return():
    # A validator that returns None (shape mismatch) must raise, mirroring the TS
    # null-return convention — not silently return None to the caller.
    origin = "https://app.example.com"
    token = {"type": "not-a-space-invite"}
    fragment = encode_link_fragment(origin, "/join", token).split("#", 1)[1]
    with pytest.raises(ValueError):
        decode_link_fragment(fragment, _space_invite_validate)
