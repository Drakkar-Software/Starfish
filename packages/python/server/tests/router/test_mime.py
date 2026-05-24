"""Unit tests for MIME pattern matching (cross-language parity with mime.test.ts)."""

import pytest

from starfish_server.router.mime import matches_allowed_mime, is_json_collection


def test_matches_exact_media_type():
    assert matches_allowed_mime("application/json", ["application/json"]) is True
    assert matches_allowed_mime("image/png", ["application/json"]) is False


def test_matches_subtype_and_full_wildcard():
    assert matches_allowed_mime("image/png", ["image/*"]) is True
    assert matches_allowed_mime("image/png", ["*/*"]) is True
    assert matches_allowed_mime("text/plain", ["image/*"]) is False


def test_strips_params_and_is_case_insensitive():
    assert matches_allowed_mime("application/JSON; charset=utf-8", ["application/json"]) is True
    assert matches_allowed_mime("IMAGE/PNG", ["image/*"]) is True


def test_is_json_collection():
    assert is_json_collection(["application/json"]) is True
    assert is_json_collection(["image/png"]) is False
    assert is_json_collection(["application/JSON"]) is True  # case-insensitive


def test_partial_glob_is_not_a_mime_wildcard():
    # Component-only matching (converged with the TS matcher): "image/p*" is a literal
    # subtype, not a glob, so it does NOT match "image/png". Only whole "*" components
    # (image/*, */*) are wildcards. See mime.test.ts for the TS twin.
    assert matches_allowed_mime("image/png", ["image/p*"]) is False
    assert matches_allowed_mime("image/png", ["image/?ng"]) is False
    assert matches_allowed_mime("application/json", ["application/*json"]) is False
