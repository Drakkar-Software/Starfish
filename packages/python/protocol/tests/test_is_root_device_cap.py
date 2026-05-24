"""Tests for ``is_root_device_cap`` (self-signed device cap detection)."""

import json
import pathlib

from starfish_protocol.cap import is_root_device_cap

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent
    / "tests"
    / "test-vectors"
    / "cap-cert.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text())


def test_true_for_self_signed_device_cap():
    # The root device's cap is minted by the root for itself, so iss == sub.
    cert = {**VECTORS["deviceCap"]["cert"], "kind": "device"}
    cert["sub"] = cert["iss"]
    assert is_root_device_cap(cert) is True


def test_false_for_paired_device_cap():
    cert = VECTORS["deviceCap"]["cert"]
    assert cert["iss"] != cert["sub"]
    assert is_root_device_cap(cert) is False


def test_false_for_member_cap():
    assert is_root_device_cap(VECTORS["memberCap"]["cert"]) is False


def test_false_for_member_cap_even_if_iss_equals_sub():
    cert = {**VECTORS["memberCap"]["cert"], "kind": "member"}
    cert["sub"] = cert["iss"]
    assert is_root_device_cap(cert) is False
