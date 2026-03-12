"""Deterministic hashing — must produce identical output to the TS implementation."""


import hashlib
import json
from typing import Any


def stable_stringify(value: Any) -> str:
    """Deterministic JSON serialization with sorted keys (recursive).

    Must produce identical output to the server's stableStringify.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value, ensure_ascii=False)
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
