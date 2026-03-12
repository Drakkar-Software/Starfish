"""Middleware utilities for FastAPI sync routes."""


import time
from dataclasses import dataclass, field

from fastapi import Request
from fastapi.responses import JSONResponse


def check_body_limit(content_length: str | None, max_bytes: int) -> JSONResponse | None:
    """Return an error response if the content length exceeds the limit."""
    if content_length is None:
        return None
    try:
        parsed = int(content_length)
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid Content-Length"}, status_code=400)
    if parsed < 0:
        return JSONResponse({"error": "Invalid Content-Length"}, status_code=400)
    if parsed > max_bytes:
        return JSONResponse({"error": "Payload too large"}, status_code=413)
    return None


@dataclass
class _BucketEntry:
    count: int = 0
    reset_at: float = 0.0


class RateLimiter:
    """In-memory rate limiter keyed by identity or client IP."""

    def __init__(self, window_ms: int = 60_000, max_requests: int = 100) -> None:
        self._window_ms = window_ms
        self._max_requests = max_requests
        self._buckets: dict[str, _BucketEntry] = {}

    def check(self, identity: str | None, request: Request | None = None) -> JSONResponse | None:
        """Return an error response if the rate limit is exceeded."""
        # Use identity if available, otherwise fall back to client IP
        bucket_key = identity
        if not bucket_key and request is not None:
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                bucket_key = forwarded.split(",")[0].strip()
            else:
                bucket_key = request.client.host if request.client else "anonymous"
        if not bucket_key:
            bucket_key = "anonymous"

        now = time.time() * 1000
        entry = self._buckets.get(bucket_key)

        if not entry or entry.reset_at <= now:
            # Clean up expired entries
            self._buckets = {
                k: v for k, v in self._buckets.items() if v.reset_at > now
            }
            entry = _BucketEntry(count=0, reset_at=now + self._window_ms)
            self._buckets[bucket_key] = entry

        entry.count += 1

        if entry.count > self._max_requests:
            return JSONResponse({"error": "Rate limit exceeded"}, status_code=429)

        return None
