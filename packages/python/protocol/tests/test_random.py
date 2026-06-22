"""Tests for starfish_protocol.random."""

import re

import pytest

from starfish_protocol.random import random_id, slugify


# ── random_id ─────────────────────────────────────────────────────────────────

def test_random_id_length():
    assert len(random_id()) == 32


def test_random_id_lowercase_hex():
    rid = random_id()
    assert re.fullmatch(r"[0-9a-f]{32}", rid), f"Not lowercase hex: {rid!r}"


def test_random_id_uniqueness():
    ids = {random_id() for _ in range(20)}
    assert len(ids) == 20, "random_id() produced a duplicate in 20 calls"


# ── slugify ───────────────────────────────────────────────────────────────────

def test_slugify_hello_world():
    assert slugify("Hello World") == "hello-world"


def test_slugify_strips_leading_trailing_spaces():
    assert slugify("  spaces  ") == "spaces"


def test_slugify_accented_chars():
    result = slugify("My Café")
    assert re.fullmatch(r"[a-z0-9-]+", result), f"Non-slug chars in: {result!r}"


def test_slugify_truncates_to_40():
    long = "a" * 50
    result = slugify(long)
    assert len(result) == 40


def test_slugify_empty_returns_fallback():
    assert slugify("") == "item"


def test_slugify_only_special_chars_returns_fallback():
    assert slugify("!!!") == "item"


def test_slugify_custom_fallback():
    assert slugify("", fallback="doc") == "doc"


def test_slugify_collapses_multiple_dashes():
    # Multiple non-alnum chars in a row → single dash
    result = slugify("hello   world")
    assert result == "hello-world"


def test_slugify_underscores_become_dashes():
    assert slugify("snake_case_name") == "snake-case-name"


def test_slugify_hyphens_preserved_collapsed():
    assert slugify("foo--bar") == "foo-bar"
