"""Deterministic hashing — must produce identical output to the TS implementation."""


import hashlib
import json
import math
from typing import Any


def _js_number(value: float) -> str:
    """Render a float the way JavaScript's ``Number → string`` does.

    The TypeScript side serializes numbers with ``JSON.stringify``, which uses the
    ECMAScript ``NumberToString`` algorithm. Python's ``repr`` and ``json.dumps``
    differ in two ways:

    1. **Negative zero / whole-number floats** — ``-0.0`` → JS ``"0"``; Python
       ``repr(-0.0)`` → ``"-0.0"``.  ``1.0`` → JS ``"1"``; Python ``"1.0"``.
    2. **Fixed vs. exponent threshold** — ECMAScript uses fixed notation when
       ``-6 < n ≤ 0`` (where n is the decimal-point position), i.e. when
       ``1e-6 ≤ |value| < 1e-4``. Python's ``repr`` switches to exponent
       at ``|value| < 1e-4``.  Values in ``[1e-6, 1e-4)`` therefore produce
       different canonical strings on each side, causing hash mismatches and
       spurious cross-language conflicts.

    This function re-implements the ECMAScript algorithm so Python's output is
    byte-identical to JS ``JSON.stringify`` for all finite IEEE-754 doubles.
    ``NaN``/``Infinity`` → ``"null"`` (JS ``JSON.stringify`` emits ``null``).
    """
    if math.isnan(value) or math.isinf(value):
        return "null"
    if value == 0:
        return "0"  # also collapses -0.0 → "0"
    if value.is_integer() and abs(value) < 1e21:
        return repr(int(value))

    # Python's repr() gives the shortest round-trip decimal since Python 3.1.
    # Parse the sign, the significant digits, and the effective exponent, then
    # reformat using ECMAScript's fixed/exponent thresholds.
    r = repr(value)

    sign = ""
    if r.startswith("-"):
        sign = "-"
        r = r[1:]

    if "e" in r:
        mantissa_s, _, exp_s = r.partition("e")
        exp_n = int(exp_s)
    else:
        mantissa_s = r
        exp_n = 0

    # Split mantissa into integer and fractional digit strings.
    if "." in mantissa_s:
        int_d, _, frac_d = mantissa_s.partition(".")
        frac_d = frac_d.rstrip("0")  # strip trailing insignificant zeros
    else:
        int_d = mantissa_s
        frac_d = ""

    digits = int_d + frac_d

    # ``decimal_pos`` = ECMAScript's ``n``: the number of significant digits
    # that sit before (or at) the decimal point in the output.  Negative means
    # the decimal point is that many places to the left of the first digit.
    decimal_pos = len(int_d) + exp_n

    if 0 < decimal_pos <= 21:
        # Normal fixed notation: one or more digits before the decimal.
        if decimal_pos >= len(digits):
            # All digits are before the decimal (large integers already handled
            # above, but non-integer-valued floats near 1e20 can reach here).
            result = digits + "0" * (decimal_pos - len(digits))
        else:
            result = digits[:decimal_pos] + "." + digits[decimal_pos:]
    elif -6 < decimal_pos <= 0:
        # Fixed notation for small fractions: "0." followed by leading zeros.
        result = "0." + "0" * (-decimal_pos) + digits
    else:
        # Exponent notation (|value| < 1e-6 or |value| >= 1e21).
        mantissa_out = digits[0] if len(digits) == 1 else digits[0] + "." + digits[1:]
        # ECMAScript exponent = decimal_pos - 1 (number of digits - 1 + raw exp)
        exp_out = decimal_pos - 1
        exp_sign = "+" if exp_out >= 0 else "-"
        result = f"{mantissa_out}e{exp_sign}{abs(exp_out)}"

    return sign + result


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
