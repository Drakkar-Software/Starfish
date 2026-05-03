"""Tests for max_leaf_timestamp (per-item appendOnly timestamp support)."""

from starfish_server.protocol.timestamps import max_leaf_timestamp


def test_plain_int_leaf():
    assert max_leaf_timestamp(42) == 42


def test_nested_dict():
    assert max_leaf_timestamp({"a": 10, "b": 20}) == 20


def test_none_returns_zero():
    assert max_leaf_timestamp(None) == 0


def test_number_list_returns_max():
    assert max_leaf_timestamp([100, 200, 300]) == 300


def test_empty_list_returns_zero():
    assert max_leaf_timestamp([]) == 0


def test_nested_dict_with_list_leaf():
    assert max_leaf_timestamp({"items": [50, 150, 250], "meta": 10}) == 250
