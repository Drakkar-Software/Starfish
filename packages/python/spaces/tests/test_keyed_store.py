"""Tests for KeyedStore and ComposedStore."""
import json
from starfish_spaces.keyed_store import create_keyed_store, create_composed_store


def test_keyed_store_set_get():
    store = create_keyed_store()
    store.set("key1", {"value": 42})
    assert store.get("key1") == {"value": 42}


def test_keyed_store_missing():
    store = create_keyed_store()
    assert store.get("missing") is None


def test_keyed_store_overwrite():
    store = create_keyed_store()
    store.set("k", "first")
    store.set("k", "second")
    assert store.get("k") == "second"


def test_keyed_store_clear_all():
    store = create_keyed_store()
    store.set("a", 1)
    store.set("b", 2)
    store.clear_all()
    assert store.get("a") is None
    assert store.get("b") is None


def test_keyed_store_serialize_hydrate():
    store = create_keyed_store()
    store.set("x", {"foo": "bar"})
    raw = store.serialize()
    store2 = create_keyed_store()
    store2.hydrate(raw)
    assert store2.get("x") == {"foo": "bar"}


def test_composed_store_two_keys():
    store = create_composed_store(lambda a, b: f"{a}:{b}")
    scoped = store.for_("space1", "user1")
    scoped.set({"edPub": "aabb"})
    assert store.for_("space1", "user1").get() == {"edPub": "aabb"}
    assert store.for_("space2", "user1").get() is None


def test_composed_store_clear_one_key():
    store = create_composed_store(lambda a, b: f"{a}:{b}")
    store.for_("s", "u").set("val")
    store.for_("s", "u").clear()
    assert store.for_("s", "u").get() is None


def test_composed_store_three_keys():
    store = create_composed_store(lambda a, b, c: f"{a}:{b}:{c}")
    store.for_("sp", "nd", "usr").set({"caps": {}})
    assert store.for_("sp", "nd", "usr").get() == {"caps": {}}
