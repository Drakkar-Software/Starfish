"""Timestamp computation and checkpoint filtering."""


import json
from typing import Any

from starfish_server.protocol.types import Timestamps


def _is_leaf(v: Any) -> bool:
    """Return True if the value is a leaf (not a plain dict)."""
    if v is None:
        return True
    if isinstance(v, list):
        return True
    return not isinstance(v, dict)


def _stable_equal(a: Any, b: Any) -> bool:
    """Deep equality for leaf values (primitives, arrays, None)."""
    if a is b:
        return True
    if a is None or b is None:
        return a is b
    if type(a) is not type(b):
        return False
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return False
        return all(_stable_equal(x, y) for x, y in zip(a, b))
    return a == b


def compute_timestamps(
    old_data: dict[str, Any] | None,
    new_data: dict[str, Any],
    old_timestamps: Timestamps | None,
    now: int,
) -> Timestamps:
    """Compute new timestamps by diffing old and new data trees.

    - Unchanged leaf values keep their old timestamp
    - Changed or new values get ``now``
    - Removed keys are omitted from the result
    """
    result: Timestamps = {}

    for key in new_data:
        new_val = new_data[key]
        old_val = old_data.get(key) if old_data else None
        old_ts = old_timestamps.get(key) if old_timestamps else None

        if _is_leaf(new_val):
            if (
                old_data is not None
                and key in old_data
                and _is_leaf(old_val)
                and _stable_equal(old_val, new_val)
                and isinstance(old_ts, int)
            ):
                result[key] = old_ts
            else:
                result[key] = now
        else:
            # Object: recurse
            new_obj = new_val
            old_obj = old_val if (not _is_leaf(old_val) and old_val is not None) else None
            old_ts_obj = old_ts if isinstance(old_ts, dict) else None
            result[key] = compute_timestamps(old_obj, new_obj, old_ts_obj, now)

    return result


def filter_by_checkpoint(
    data: dict[str, Any],
    timestamps: Timestamps,
    checkpoint: int,
) -> dict[str, Any]:
    """Filter data to only include paths where the timestamp > checkpoint."""
    result: dict[str, Any] = {}

    for key in data:
        val = data[key]
        ts = timestamps.get(key)

        if ts is None:
            continue

        if isinstance(ts, int):
            if ts > checkpoint:
                result[key] = val
        else:
            # Nested object timestamps
            if _is_leaf(val):
                # Mismatch: timestamps say object but data is leaf
                result[key] = val
            else:
                filtered = filter_by_checkpoint(val, ts, checkpoint)
                if filtered:
                    result[key] = filtered

    return result
