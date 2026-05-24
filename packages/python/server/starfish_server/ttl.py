"""TTL / document expiration utilities."""


import time


def is_expired(timestamp: float, ttl_ms: int) -> bool:
    """Check if a document has expired based on its last-modified timestamp and TTL."""
    if timestamp == 0:
        return False  # Never written — not expired
    return (time.time() * 1000) - timestamp > ttl_ms
