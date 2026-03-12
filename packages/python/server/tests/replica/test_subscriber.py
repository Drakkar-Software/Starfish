"""Tests for SubscriptionStore."""


import pytest

from starfish_server.replica.subscriber import SubscriptionStore
from tests.helpers import MemoryObjectStore


@pytest.fixture
def store():
    return SubscriptionStore(MemoryObjectStore())


async def test_add_and_list(store):
    await store.add("https://replica.example.com", ["posts", "settings"], subscribed_at=1000)
    subs = await store.list_for_collection("posts")
    assert len(subs) == 1
    assert subs[0].webhook_url == "https://replica.example.com"
    assert "posts" in subs[0].collections


async def test_list_filters_by_collection(store):
    await store.add("https://a.example.com", ["posts"], subscribed_at=1000)
    await store.add("https://b.example.com", ["settings"], subscribed_at=1001)
    posts_subs = await store.list_for_collection("posts")
    settings_subs = await store.list_for_collection("settings")
    assert len(posts_subs) == 1
    assert posts_subs[0].webhook_url == "https://a.example.com"
    assert len(settings_subs) == 1
    assert settings_subs[0].webhook_url == "https://b.example.com"


async def test_add_replaces_existing_url(store):
    await store.add("https://replica.example.com", ["posts"], subscribed_at=1000)
    await store.add("https://replica.example.com", ["settings"], subscribed_at=2000)
    all_subs = await store.list_all()
    assert len(all_subs) == 1
    assert all_subs[0].collections == ["settings"]


async def test_remove(store):
    await store.add("https://replica.example.com", ["posts"], subscribed_at=1000)
    await store.remove("https://replica.example.com")
    subs = await store.list_for_collection("posts")
    assert subs == []


async def test_remove_missing_is_noop(store):
    await store.remove("https://does-not-exist.example.com")  # should not raise


async def test_list_all(store):
    await store.add("https://a.example.com", ["posts"], subscribed_at=1000)
    await store.add("https://b.example.com", ["settings"], subscribed_at=1001)
    all_subs = await store.list_all()
    assert len(all_subs) == 2


async def test_persists_across_instances():
    """Subscriptions survive reconstruction of SubscriptionStore from the same backing store."""
    mem = MemoryObjectStore()
    store1 = SubscriptionStore(mem)
    await store1.add("https://replica.example.com", ["posts"], subscribed_at=1000)

    store2 = SubscriptionStore(mem)
    subs = await store2.list_for_collection("posts")
    assert len(subs) == 1
