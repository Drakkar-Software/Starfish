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


def test_non_finite_floats_serialize_as_null_and_hash_identically():
    # NaN/±Infinity are not valid JSON; both languages render them as "null"
    # (JS via JSON.stringify, Python via _js_number). This is a deliberate
    # cross-language invariant that no JSON vector can encode, and it guards a
    # real regression: Python's json.dumps(float("nan")) emits bare ``NaN``
    # (invalid JSON), so a refactor routing floats through json.dumps would break
    # cross-language hashing silently.
    nan, inf, ninf = float("nan"), float("inf"), float("-inf")
    assert stable_stringify(nan) == "null"
    assert stable_stringify(inf) == "null"
    assert stable_stringify(ninf) == "null"
    # Recursion path: non-finite floats nested in containers.
    assert stable_stringify({"a": nan, "b": [inf]}) == '{"a":null,"b":[null]}'
    # All three collapse to "null" ⇒ identical document hash — the property sync relies on.
    assert compute_hash({"x": nan}) == compute_hash({"x": inf}) == compute_hash({"x": ninf})
