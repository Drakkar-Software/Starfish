"""Deterministic hashing — must produce identical output to the TS implementation."""


import hashlib
import json
import math
from typing import Any


def _js_number(value: float) -> str:
    """Render a float the way JavaScript's ``Number → string`` does.

    The TypeScript side serializes numbers with ``JSON.stringify``. JavaScript
    has a single IEEE-754 double type, so it cannot distinguish ``1.0`` from
    ``1`` and renders ``-0`` as ``0``. Python's ``json.dumps`` would instead emit
    ``"1.0"`` / ``"-0.0"``, diverging across languages and breaking cross-language
    hashing and signatures for any document carrying a whole-number float or a
    negative zero. This matches JavaScript's output for those cases.

    ``NaN`` / ``Infinity`` are not valid JSON; ``JSON.stringify`` emits ``null``,
    so we do too. Numbers whose magnitude forces exponent notation in a range
    where JavaScript and Python disagree on the fixed/exponent threshold (very
    small/large non-integers) may still differ — represent such fields as
    strings if cross-language hashing is required.
    """
    if math.isnan(value) or math.isinf(value):
        return "null"
    if value == 0:
        return "0"  # also collapses -0.0 → "0"
    if value.is_integer() and abs(value) < 1e21:
        return repr(int(value))
    s = repr(value)
    if "e" in s:  # normalize Python's "1e-07" to JS's "1e-7"
        mantissa, _, exp = s.partition("e")
        exp_n = int(exp)
        s = f"{mantissa}e{'+' if exp_n >= 0 else '-'}{abs(exp_n)}"
    return s


def stable_stringify(value: Any) -> str:
    """Deterministic JSON serialization with sorted keys (recursive).

    Must produce identical output to the server's stableStringify.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        # JavaScript has only IEEE-754 doubles: integers beyond 2**53 lose
        # precision and magnitudes >= 1e21 switch to exponent notation. The TS
        # side serializes via JSON.stringify, so a large integer in a document
        # body must be rendered the way JS would — otherwise the canonical string
        # (and document hash) diverges across languages. Within the safe range
        # the exact integer is emitted.
        if -(2**53) < value < 2**53:
            return json.dumps(value, ensure_ascii=False)
        return _js_number(float(value))
    if isinstance(value, float):
        return _js_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(stable_stringify(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys())
        pairs = [json.dumps(k, ensure_ascii=False) + ":" + stable_stringify(value[k]) for k in keys]
        return "{" + ",".join(pairs) + "}"
    return "null"


def compute_hash(data: dict[str, Any]) -> str:
    """Compute SHA-256 hex digest of the stable-stringified data."""
    encoded = stable_stringify(data).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
