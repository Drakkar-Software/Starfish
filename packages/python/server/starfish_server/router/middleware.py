"""Middleware utilities for FastAPI sync routes."""


import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable, Sequence

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware


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


# --- CORS Configuration ---

@dataclass
class CorsConfig:
    """CORS configuration passed to Starlette CORSMiddleware."""
    allow_origins: list[str] = field(default_factory=lambda: ["*"])
    allow_methods: list[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
    allow_headers: list[str] = field(default_factory=lambda: ["Content-Type", "Authorization", "Accept"])
    expose_headers: list[str] = field(default_factory=list)
    max_age: int = 86400
    allow_credentials: bool = False


# --- Security Headers Middleware ---

@dataclass
class SecurityHeadersConfig:
    """Configuration for security response headers."""
    content_type_options: str | None = "nosniff"
    frame_options: str | None = "DENY"
    strict_transport_security: str | None = "max-age=31536000; includeSubDomains"
    xss_protection: str | None = "1; mode=block"
    referrer_policy: str | None = "strict-origin-when-cross-origin"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware that adds security headers to every response."""

    def __init__(self, app: Any, config: SecurityHeadersConfig | None = None) -> None:
        super().__init__(app)
        self._headers: list[tuple[str, str]] = []
        cfg = config or SecurityHeadersConfig()
        if cfg.content_type_options:
            self._headers.append(("X-Content-Type-Options", cfg.content_type_options))
        if cfg.frame_options:
            self._headers.append(("X-Frame-Options", cfg.frame_options))
        if cfg.strict_transport_security:
            self._headers.append(("Strict-Transport-Security", cfg.strict_transport_security))
        if cfg.xss_protection:
            self._headers.append(("X-XSS-Protection", cfg.xss_protection))
        if cfg.referrer_policy:
            self._headers.append(("Referrer-Policy", cfg.referrer_policy))

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for key, value in self._headers:
            response.headers[key] = value
        return response


# --- Request Timeout Middleware ---

class RequestTimeoutMiddleware(BaseHTTPMiddleware):
    """Middleware that enforces a per-request timeout (returns 408 on expiry)."""

    def __init__(self, app: Any, timeout_ms: int = 30_000) -> None:
        super().__init__(app)
        self._timeout_s = timeout_ms / 1000.0

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            return await asyncio.wait_for(call_next(request), timeout=self._timeout_s)
        except asyncio.TimeoutError:
            return JSONResponse({"error": "Request timeout"}, status_code=408)


# --- Middleware Configurator ---

def configure_middleware(
    app: FastAPI,
    *,
    cors: CorsConfig | bool | None = None,
    security_headers: SecurityHeadersConfig | bool | None = None,
    compression: bool = False,
    compression_minimum_size: int = 500,
    request_timeout_ms: int | None = None,
) -> None:
    """Configure standard middleware on a FastAPI application.

    Call this AFTER ``app.include_router(...)`` so middleware wraps all routes.
    Middleware is applied in reverse order of addition (outermost first).
    """
    # Request timeout (innermost — closest to the handler)
    if request_timeout_ms is not None:
        app.add_middleware(RequestTimeoutMiddleware, timeout_ms=request_timeout_ms)

    # Security headers
    if security_headers is not None and security_headers is not False:
        cfg = security_headers if isinstance(security_headers, SecurityHeadersConfig) else SecurityHeadersConfig()
        app.add_middleware(SecurityHeadersMiddleware, config=cfg)

    # GZip compression
    if compression:
        app.add_middleware(GZipMiddleware, minimum_size=compression_minimum_size)

    # CORS (outermost — must run before everything else)
    if cors is not None and cors is not False:
        cfg = cors if isinstance(cors, CorsConfig) else CorsConfig()
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cfg.allow_origins,
            allow_methods=cfg.allow_methods,
            allow_headers=cfg.allow_headers,
            expose_headers=cfg.expose_headers,
            max_age=cfg.max_age,
            allow_credentials=cfg.allow_credentials,
        )
