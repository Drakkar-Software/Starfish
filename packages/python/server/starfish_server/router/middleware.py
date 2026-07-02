"""Middleware utilities for FastAPI sync routes."""


import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable, Sequence

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware

from starfish_server.storage.kv_adapter import KVAdapter, create_in_memory_kv_adapter


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


class RateLimiter:
    """Rate limiter keyed by identity and/or client IP, backed by a :class:`KVAdapter`."""

    def __init__(
        self,
        window_ms: int = 60_000,
        max_requests: int = 100,
        max_buckets: int = 10_000,
        bucket_mode: str = "identity",
        kv: KVAdapter | None = None,
        key_prefix: str = "",
        trusted_proxy_hops: int = 0,
    ) -> None:
        self._window_ms = window_ms
        self._max_requests = max_requests
        self._bucket_mode = bucket_mode
        # ``max_buckets`` bounds the default in-memory store; ignored when a shared ``kv``
        # is supplied (that backend owns its own capacity policy / TTL-based bounding).
        self._kv = kv or create_in_memory_kv_adapter(max_keys=max_buckets)
        self._key_prefix = key_prefix
        # Number of trusted reverse-proxy hops directly in front of this server.
        # ``0`` (default) means the client-controlled ``X-Forwarded-For`` header is
        # NOT trusted for bucketing — the socket peer is used instead, so a spoofed
        # XFF cannot mint fresh buckets. ``N > 0`` takes the client as the Nth entry
        # FROM THE RIGHT of XFF (each trusted proxy appends the peer it received the
        # request from). Identical semantics to the TS ``trustedProxyHops`` option.
        self._trusted_proxy_hops = trusted_proxy_hops

    def _resolve_ip_part(
        self, forwarded_for: str | None, client_ip: str | None
    ) -> str:
        """Resolve the IP component of the bucket key. Identical to the TS
        ``RateLimiter._resolveIpPart``.

        With ``trusted_proxy_hops == 0`` (default) XFF is ignored entirely — a
        spoofed header cannot create a new bucket. With ``N > 0`` the Nth-from-right
        XFF entry (the real client behind N trusted proxies) is used; if the header
        is shorter than N, it is not trusted and the socket peer is used instead.
        """
        if self._trusted_proxy_hops > 0:
            hops = (
                [h.strip() for h in forwarded_for.split(",") if h.strip()]
                if forwarded_for
                else []
            )
            if len(hops) >= self._trusted_proxy_hops:
                return hops[len(hops) - self._trusted_proxy_hops]
            # Fewer hops than expected → the chain is not the trusted shape; fall
            # back to the socket peer (coarse, but not attacker-spoofable).
            return client_ip or "anonymous"
        # Default: do NOT trust the client-controlled XFF. Bucket by the runtime
        # socket/peer IP, sharing one "anonymous" bucket when unavailable.
        return client_ip or "anonymous"

    async def check(
        self,
        identity: str | None,
        forwarded_for: str | None = None,
        client_ip: str | None = None,
    ) -> JSONResponse | None:
        """Return an error response if the rate limit is exceeded.

        Bucket-key precedence: in ``"identity"`` mode, authenticated identity →
        resolved IP part → shared ``"anonymous"``. In ``"ip"`` mode the identity is
        ignored and bucketing is by the resolved IP only. In ``"identity+ip"`` mode
        the key is the (identity, ip) pair. The IP part is derived by
        ``_resolve_ip_part``, which by default ignores the spoofable
        X-Forwarded-For header (see ``trusted_proxy_hops``). Identical to the TS
        RateLimiter; the only difference is which signals a runtime supplies (the
        Python server can pass the socket ``request.client.host`` as ``client_ip``;
        Hono cannot).
        """
        ip_part = self._resolve_ip_part(forwarded_for, client_ip)

        if self._bucket_mode == "ip":
            bucket_key = ip_part
        elif self._bucket_mode == "identity+ip":
            bucket_key = f"{identity or 'anonymous'}|{ip_part}"
        else:
            bucket_key = identity or ip_part

        count = await self._kv.increment(self._key_prefix + bucket_key, self._window_ms)
        if count > self._max_requests:
            return JSONResponse({"error": "Rate limit exceeded"}, status_code=429)
        return None


async def check_rate_limiters(
    limiters: Sequence["RateLimiter"],
    identity: str | None,
    forwarded_for: str | None = None,
    client_ip: str | None = None,
) -> JSONResponse | None:
    """Apply a list of rate limiters to one request; return the first 429, else None.

    A single-counter rule supplies one limiter; a two-independent rule (per-identity AND
    per-ip) supplies two — the request is rejected if either dimension is over budget.
    Every limiter is consulted (each increments its counter) before returning, so the
    dimensions stay in lock-step regardless of order. Mirrors the TS ``checkRateLimiters``.
    """
    first_error: JSONResponse | None = None
    for rl in limiters:
        error = await rl.check(identity, forwarded_for, client_ip)
        if error is not None and first_error is None:
            first_error = error
    return first_error


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
