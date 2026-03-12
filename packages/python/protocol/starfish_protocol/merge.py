"""Document merge utilities for conflict resolution."""


from typing import Any


def deep_merge(local: dict[str, Any], remote: dict[str, Any]) -> dict[str, Any]:
    """Remote-wins deep merge.

    Recursively merges *remote* into *local*: nested dicts present on both sides
    are merged recursively; for all other values the remote value wins.

    This is the canonical conflict resolution strategy used across the Starfish
    protocol — both the client SDK and the server-side replica manager rely on it.
    """
    merged = {**local}
    for key, remote_val in remote.items():
        local_val = merged.get(key)
        if isinstance(remote_val, dict) and isinstance(local_val, dict):
            merged[key] = deep_merge(local_val, remote_val)
        else:
            merged[key] = remote_val
    return merged
