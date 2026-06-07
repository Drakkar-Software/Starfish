"""Cross-language conformance: the Python CRDT must fold the shared vectors to
the same materialized state as the TypeScript implementation."""

import json
from functools import cmp_to_key
from pathlib import Path

from starfish_wal import WalCrdt, compare_clocks

VECTORS = json.loads(
    (Path(__file__).resolve().parents[4] / "tests" / "test-vectors" / "wal-crdt.json").read_text()
)


def _sign(n: int) -> int:
    return (n > 0) - (n < 0)


def test_clock_total_order():
    for case in VECTORS["clockOrder"]:
        assert _sign(compare_clocks(case["a"], case["b"])) == case["sign"]


def test_fold_cases_converge_and_are_idempotent():
    for f in VECTORS["fold"]:
        ops = f["ops"]
        expected = f["expected"]

        forward = WalCrdt()
        forward.fold(ops)
        assert forward.materialize() == expected, f["name"]

        reverse = WalCrdt()
        reverse.fold(list(reversed(ops)))
        assert reverse.materialize() == expected, f["name"]

        by_clock = WalCrdt()
        by_clock.fold(sorted(ops, key=cmp_to_key(lambda a, b: compare_clocks(a["clock"], b["clock"]))))
        assert by_clock.materialize() == expected, f["name"]

        twice = WalCrdt()
        twice.fold(ops)
        twice.fold(ops)
        assert twice.materialize() == expected, f["name"]

        for list_name, text in f.get("expectedText", {}).items():
            assert forward.text(list_name) == text, f["name"]
