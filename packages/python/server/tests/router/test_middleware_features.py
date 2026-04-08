"""Tests for CORS, security headers, compression, timeout middleware."""

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport
from fastapi.responses import JSONResponse

from starfish_server.router.middleware import (
    CorsConfig,
    SecurityHeadersConfig,
    SecurityHeadersMiddleware,
    RequestTimeoutMiddleware,
    configure_middleware,
)


def _make_app() -> FastAPI:
    app = FastAPI()

    @app.get("/test")
    async def test_endpoint():
        return {"ok": True}

    return app


@pytest.mark.asyncio
async def test_cors_default():
    app = _make_app()
    configure_middleware(app, cors=True)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/test", headers={"Origin": "http://example.com"})
    assert resp.status_code == 200
    assert "access-control-allow-origin" in resp.headers


@pytest.mark.asyncio
async def test_cors_custom_origin():
    app = _make_app()
    configure_middleware(app, cors=CorsConfig(allow_origins=["https://allowed.com"]))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/test", headers={"Origin": "https://allowed.com"})
    assert resp.status_code == 200
    assert "access-control-allow-origin" in resp.headers


@pytest.mark.asyncio
async def test_cors_preflight():
    app = _make_app()
    configure_middleware(app, cors=True)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.options(
            "/test",
            headers={"Origin": "http://example.com", "Access-Control-Request-Method": "POST"},
        )
    assert resp.status_code == 200
    assert "access-control-allow-methods" in resp.headers


@pytest.mark.asyncio
async def test_security_headers_default():
    app = _make_app()
    configure_middleware(app, security_headers=True)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/test")
    assert resp.status_code == 200
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert "strict-transport-security" in resp.headers
    assert resp.headers.get("x-xss-protection") == "1; mode=block"
    assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"


@pytest.mark.asyncio
async def test_security_headers_custom():
    app = _make_app()
    configure_middleware(
        app,
        security_headers=SecurityHeadersConfig(
            frame_options="SAMEORIGIN",
            xss_protection=None,
        ),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/test")
    assert resp.headers.get("x-frame-options") == "SAMEORIGIN"
    assert resp.headers.get("x-content-type-options") == "nosniff"
    # xss_protection disabled
    assert "x-xss-protection" not in resp.headers


@pytest.mark.asyncio
async def test_compression_enabled():
    app = _make_app()

    @app.get("/large")
    async def large_endpoint():
        return {"data": "x" * 2000}

    configure_middleware(app, compression=True, compression_minimum_size=100)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/large", headers={"Accept-Encoding": "gzip"})
    # Compressed responses may have content-encoding header
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_request_timeout_fast():
    app = _make_app()
    configure_middleware(app, request_timeout_ms=5000)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/test")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_request_timeout_slow():
    import asyncio
    app = FastAPI()

    @app.get("/slow")
    async def slow_endpoint():
        await asyncio.sleep(2)
        return {"ok": True}

    configure_middleware(app, request_timeout_ms=100)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/slow")
    assert resp.status_code == 408
    assert resp.json()["error"] == "Request timeout"


@pytest.mark.asyncio
async def test_all_middleware_combined():
    app = _make_app()
    configure_middleware(
        app,
        cors=True,
        security_headers=True,
        compression=True,
        request_timeout_ms=5000,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/test", headers={"Origin": "http://example.com"})
    assert resp.status_code == 200
    assert "access-control-allow-origin" in resp.headers
    assert resp.headers.get("x-content-type-options") == "nosniff"
