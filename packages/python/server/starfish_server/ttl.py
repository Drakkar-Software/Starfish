"""TTL / document expiration utilities."""


import time


def is_expired(timestamp: float, ttl_ms: int | None) -> bool:
    """Check if a document has expired based on its last-modified timestamp and TTL."""
    if timestamp == 0:
        return False  # Never written — not expired
    # Match packages/ts/server/src/ttl.ts: non-positive or missing TTL never expires.
    if ttl_ms is None or ttl_ms <= 0:
        return False
    return (time.time() * 1000) - timestamp > ttl_ms
