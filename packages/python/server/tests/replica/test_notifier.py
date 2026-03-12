"""Tests for NotificationPublisher."""


import hashlib
import hmac
import json

import httpx
import pytest
import respx

from starfish_server.replica.notifier import NotificationPublisher, verify_signature
from starfish_server.replica.subscriber import SubscriptionStore
from tests.helpers import MemoryObjectStore


def _sign(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


@pytest.fixture
def sub_store():
    return SubscriptionStore(MemoryObjectStore())


@respx.mock
async def test_notify_sends_post(sub_store):
    await sub_store.add("https://replica.example.com", ["posts"], subscribed_at=1000)

    route = respx.post("https://replica.example.com/replica/notify").respond(200, json={"ok": True})

    async with httpx.AsyncClient() as client:
        publisher = NotificationPublisher(sub_store, client=client)
        await publisher.notify("posts", "abc123", 9000)

    assert route.called
    body = json.loads(route.calls[0].request.content)
    assert body["collection"] == "posts"
    assert body["hash"] == "abc123"
    assert body["timestamp"] == 9000


@respx.mock
async def test_notify_includes_hmac_signature(sub_store):
    await sub_store.add("https://replica.example.com", ["posts"], subscribed_at=1000)
    respx.post("https://replica.example.com/replica/notify").respond(200, json={"ok": True})

    async with httpx.AsyncClient() as client:
        publisher = NotificationPublisher(sub_store, client=client, webhook_secret="mysecret")
        await publisher.notify("posts", "abc123", 9000)

    req = respx.calls[0].request
    sig = req.headers.get("X-Starfish-Signature", "")
    assert sig.startswith("sha256=")
    assert verify_signature(req.content, sig, "mysecret")


@respx.mock
async def test_notify_skips_unknown_collection(sub_store):
    await sub_store.add("https://replica.example.com", ["settings"], subscribed_at=1000)
    # No route registered — would raise if called
    async with httpx.AsyncClient() as client:
        publisher = NotificationPublisher(sub_store, client=client)
        await publisher.notify("posts", "abc123", 9000)  # no subscribers for "posts"


@respx.mock
async def test_notify_tolerates_delivery_failure(sub_store):
    await sub_store.add("https://replica.example.com", ["posts"], subscribed_at=1000)
    respx.post("https://replica.example.com/replica/notify").respond(500)

    async with httpx.AsyncClient() as client:
        publisher = NotificationPublisher(sub_store, client=client)
        # Should not raise even on server error
        await publisher.notify("posts", "abc123", 9000)


@respx.mock
async def test_notify_fans_out_to_multiple_subscribers(sub_store):
    """All registered subscribers for a collection receive the notification."""
    await sub_store.add("https://replica-a.example.com", ["posts"], subscribed_at=1000)
    await sub_store.add("https://replica-b.example.com", ["posts"], subscribed_at=1001)
    route_a = respx.post("https://replica-a.example.com/replica/notify").respond(200, json={"ok": True})
    route_b = respx.post("https://replica-b.example.com/replica/notify").respond(200, json={"ok": True})

    async with httpx.AsyncClient() as client:
        publisher = NotificationPublisher(sub_store, client=client)
        await publisher.notify("posts", "abc123", 9000)

    assert route_a.called
    assert route_b.called


def test_verify_signature_valid():
    body = b'{"collection":"posts"}'
    secret = "supersecret"
    sig = _sign(body, secret)
    assert verify_signature(body, sig, secret)


def test_verify_signature_invalid():
    body = b'{"collection":"posts"}'
    assert not verify_signature(body, "sha256=deadbeef", "supersecret")
