"""Document merge utilities for conflict resolution."""


from typing import Any

UNSAFE_KEYS = frozenset({"__proto__", "constructor", "prototype", "__class__", "__dict__"})


def deep_merge(local: dict[str, Any], remote: dict[str, Any]) -> dict[str, Any]:
    """Remote-wins deep merge.

    Recursively merges *remote* into *local*: nested dicts present on both sides
    are merged recursively; for all other values the remote value wins.

    Keys in UNSAFE_KEYS are dropped at every depth to prevent prototype/dunder
    injection from untrusted remote payloads.
    """
    merged = {k: v for k, v in local.items() if k not in UNSAFE_KEYS}
    for key, remote_val in remote.items():
        if key in UNSAFE_KEYS:
            continue
        local_val = merged.get(key)
        if isinstance(remote_val, dict) and isinstance(local_val, dict):
            merged[key] = deep_merge(local_val, remote_val)
        else:
            merged[key] = remote_val
    return merged
