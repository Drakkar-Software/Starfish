"""Test harness: drive the chat app's FastAPI server in-process via the Python
SDK + extensions, exercising the full v3 library chain (protocol → server → SDK
+ identities + keyring + sharing + entitlements + queuing + audit).

`STARFISH_DATA_DIR` is pointed at an isolated tmp dir before `server` is imported
so the filesystem store never touches the real ./data.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any

# Must be set BEFORE importing `server` (the store + demo-secret are read at import time).
os.environ.setdefault("STARFISH_DATA_DIR", tempfile.mkdtemp(prefix="starfish-chat-test-"))
# The demo/admin endpoints (`/demo/grant`, `/demo/revoke`, `/audit`) are gated behind
# this shared secret; the `http` fixture sends it by default so existing tests pass.
DEMO_SECRET = "test-demo-secret"
os.environ.setdefault("STARFISH_DEMO_SECRET", DEMO_SECRET)

import httpx
import pytest_asyncio

import server  # noqa: E402  (import after env is set)
from starfish_sdk import StarfishClient

# Sync routes are mounted at the server root, so the SDK base URL is the origin.
# ASGITransport synthesises host `testserver`; the SDK signs the request bound to
# the same host, so the per-request signature verifies byte-for-byte.
BASE_URL = "http://testserver"


class CapProvider:
    """Adapts a cap-cert + device Ed25519 private key into the SDK CapProvider."""

    def __init__(self, cap: dict[str, Any], dev_ed_priv_hex: str) -> None:
        self._cap = cap
        self._dev = dev_ed_priv_hex

    async def get_cap(self) -> dict[str, Any]:
        return {"cap": self._cap, "dev_ed_priv_hex": self._dev}


@pytest_asyncio.fixture
async def http():
    """Raw httpx client bound to the in-process ASGI app (for /health, /demo, …).

    Sends the demo-admin secret by default so `/demo/*` and `/audit` work
    transparently; tests that probe the gate override `X-Demo-Secret` per request.
    """
    transport = httpx.ASGITransport(app=server.app)
    async with httpx.AsyncClient(
        transport=transport, base_url=BASE_URL, headers={"X-Demo-Secret": DEMO_SECRET}
    ) as client:
        yield client


@pytest_asyncio.fixture
def sdk(http):
    """Factory: build a Starfish SDK client for a given cap, sharing the ASGI httpx client."""

    def _make(cap: dict[str, Any] | None = None, dev_ed_priv_hex: str | None = None) -> StarfishClient:
        provider = CapProvider(cap, dev_ed_priv_hex) if cap is not None else None
        return StarfishClient(BASE_URL, cap_provider=provider, client=http)

    return _make


# ── Scope builders (mirror the frontend) ──────────────────────────────────────
def owner_scope() -> dict[str, Any]:
    """Full access to every room + its keyring + member directory."""
    return {
        "ops": ["read", "list", "write"],
        "collections": ["chat"],
        "paths": ["chat/rooms/**", "chatkeyring/rooms/**", "chatmembers/rooms/**"],
    }


def member_scope(room_id: str, can_write: bool) -> dict[str, Any]:
    """Access to ONE room: its doc + keyring (read-only members omit `write`)."""
    return {
        "ops": ["read", "list", "write"] if can_write else ["read", "list"],
        "collections": ["chat"],
        "paths": [f"chat/rooms/{room_id}", f"chatkeyring/rooms/{room_id}/_keyring"],
    }


def account_scope(user_id: str) -> dict[str, Any]:
    """The caller's own namespace: read entitlements + read/write profile."""
    return {
        "ops": ["read", "list", "write"],
        "collections": ["entitlements", "profile"],
        "paths": [f"users/{user_id}/entitlements", f"user/{user_id}/profile"],
    }
