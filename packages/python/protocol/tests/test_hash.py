"""Tests for hashing using shared test vectors."""

import json
import pathlib

import pytest

from starfish_protocol.hash import stable_stringify, compute_hash

VECTORS_PATH = pathlib.Path(__file__).parent.parent.parent.parent.parent / "tests" / "test-vectors" / "hash.json"
VECTORS = json.loads(VECTORS_PATH.read_text())


@pytest.mark.parametrize("case", VECTORS["stableStringify"])
def test_stable_stringify(case):
    result = stable_stringify(case["input"])
    assert result == case["expected"]


@pytest.mark.parametrize("case", VECTORS["computeHash"])
def test_compute_hash(case):
    assert stable_stringify(case["input"]) == case["stableJson"]
    assert compute_hash(case["input"]) == case["expectedHash"]
