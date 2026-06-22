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
    if not isinstance(tok, list) or len(tok) != 3:
        raise ValueError("bad shape")
    origin, path, token = tok
    if not isinstance(token, dict):
        raise ValueError("bad token")
    return {"origin": origin, "path": path, "token": token}


def test_link_fragment_round_trip():
    origin = "https://app.example.com"
    path = "/join"
    token = {"type": "space-invite", "id": "xyz123", "role": "writer"}

    url = encode_link_fragment(origin, path, token)
    assert url.startswith("https://app.example.com/join#")

    fragment = url.split("#", 1)[1]
    result = decode_link_fragment(fragment, _space_invite_validate)

    assert result["origin"] == origin
    assert result["path"] == path
    assert result["token"] == token


def test_decode_link_fragment_strips_hash_prefix():
    origin = "https://app.example.com"
    path = "/invite"
    token = {"type": "member-invite", "id": "abc"}

    url = encode_link_fragment(origin, path, token)
    fragment_with_hash = "#" + url.split("#", 1)[1]
    result = decode_link_fragment(fragment_with_hash, _space_invite_validate)
    assert result["token"] == token


def test_decode_link_fragment_raises_on_invalid():
    with pytest.raises(ValueError):
        decode_link_fragment("not-valid-base64url!!!", _space_invite_validate)


def test_decode_link_fragment_raises_on_bad_shape():
    # Valid base64url but wrong shape
    import json, base64
    bad = base64.urlsafe_b64encode(json.dumps({"not": "a list"}).encode()).decode().rstrip("=")
    with pytest.raises(ValueError):
        decode_link_fragment(bad, _space_invite_validate)
