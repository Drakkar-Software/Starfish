"""Tests for SpaceAccessError."""
from starfish_spaces.space_access_error import SpaceAccessError


def test_space_access_error_has_space_id():
    err = SpaceAccessError("sp-abc", None)
    assert err.space_id == "sp-abc"
    assert err.node_id is None


def test_space_access_error_with_node_id():
    err = SpaceAccessError("sp-abc", "obj-123")
    assert err.space_id == "sp-abc"
    assert err.node_id == "obj-123"


def test_space_access_error_is_exception():
    err = SpaceAccessError("sp-xyz")
    assert isinstance(err, Exception)


def test_space_access_error_message():
    err = SpaceAccessError("sp-abc", "obj-123", "Access denied.")
    assert "sp-abc" in str(err) or "Access denied." in str(err)
