"""Tests for make_registry_role_enricher.

Mirror of TS ``tests/registry-role-enricher.test.ts``.
"""

import json

import pytest

from starfish_server.router.route_builder import AuthResult
from starfish_server.storage.base import StoreContext
from starfish_server.storage.memory import MemoryObjectStore
from starfish_sharing import make_registry_role_enricher

REGISTRY_PATH = "products/{id}/_registry"
OWNER = "product:owner"
MEMBER = "product:member"


def _enricher(store, *, allow_tofu=True):
    return make_registry_role_enricher(
        store,
        id_param="productId",
        registry_path=REGISTRY_PATH,
        owner_role=OWNER,
        member_role=MEMBER,
        allow_tofu=allow_tofu,
    )


def _write_registry(store: MemoryObjectStore, product_id: str, doc: dict) -> None:
    store._data[f"products/{product_id}/_registry"] = json.dumps(doc)


def _auth(identity: str) -> AuthResult:
    return AuthResult(identity=identity, roles=[])


class _RaisingStore(MemoryObjectStore):
    async def get_string(self, key: str, *, context: StoreContext | None = None):
        raise RuntimeError("store boom")


async def test_missing_doc_tofu_grants_owner_and_member():
    store = MemoryObjectStore(data={})
    roles = await _enricher(store)(_auth("alice"), {"productId": "p1"})
    assert roles == [OWNER, MEMBER]


async def test_missing_doc_strict_grants_nothing():
    store = MemoryObjectStore(data={})
    roles = await _enricher(store, allow_tofu=False)(_auth("alice"), {"productId": "p1"})
    assert roles == []


async def test_store_error_propagates():
    enricher = _enricher(_RaisingStore(data={}))
    with pytest.raises(RuntimeError, match="store boom"):
        await enricher(_auth("alice"), {"productId": "p1"})


async def test_owner_less_doc_denies():
    store = MemoryObjectStore(data={})
    _write_registry(store, "p1", {"data": {"members": ["alice"]}})
    roles = await _enricher(store)(_auth("alice"), {"productId": "p1"})
    assert roles == []


async def test_owner_match_grants_owner_and_member():
    store = MemoryObjectStore(data={})
    _write_registry(store, "p1", {"data": {"owner": "alice", "members": []}})
    roles = await _enricher(store)(_auth("alice"), {"productId": "p1"})
    assert roles == [OWNER, MEMBER]


async def test_member_match_grants_member_only():
    store = MemoryObjectStore(data={})
    _write_registry(store, "p1", {"data": {"owner": "alice", "members": ["bob"]}})
    roles = await _enricher(store)(_auth("bob"), {"productId": "p1"})
    assert roles == [MEMBER]


async def test_stranger_gets_nothing():
    store = MemoryObjectStore(data={})
    _write_registry(store, "p1", {"data": {"owner": "alice", "members": ["bob"]}})
    roles = await _enricher(store)(_auth("carol"), {"productId": "p1"})
    assert roles == []


async def test_bad_id_fails_fullmatch():
    store = MemoryObjectStore(data={})
    roles = await _enricher(store)(_auth("alice"), {"productId": "bad id!"})
    assert roles == []


async def test_trailing_newline_id_denied():
    # Even though the registry exists for "p1", "p1\n" must fail fullmatch and
    # never look up "p1\n" — fail closed.
    store = MemoryObjectStore(data={})
    _write_registry(store, "p1", {"data": {"owner": "alice", "members": []}})
    roles = await _enricher(store)(_auth("alice"), {"productId": "p1\n"})
    assert roles == []


async def test_missing_id_param():
    store = MemoryObjectStore(data={})
    roles = await _enricher(store)(_auth("alice"), {})
    assert roles == []


async def test_empty_identity():
    store = MemoryObjectStore(data={})
    roles = await _enricher(store)(_auth(""), {"productId": "p1"})
    assert roles == []


async def test_bare_object_doc_parsed():
    store = MemoryObjectStore(data={})
    # No {"data": ...} wrapper — bare object.
    _write_registry(store, "p1", {"owner": "alice", "members": ["bob"]})
    assert await _enricher(store)(_auth("alice"), {"productId": "p1"}) == [OWNER, MEMBER]
    assert await _enricher(store)(_auth("bob"), {"productId": "p1"}) == [MEMBER]


async def test_data_wrapped_doc_parsed():
    store = MemoryObjectStore(data={})
    _write_registry(store, "p1", {"data": {"owner": "alice", "members": ["bob"]}})
    assert await _enricher(store)(_auth("bob"), {"productId": "p1"}) == [MEMBER]


async def test_unparseable_doc_denies():
    store = MemoryObjectStore(data={})
    store._data["products/p1/_registry"] = "not json{{"
    roles = await _enricher(store)(_auth("alice"), {"productId": "p1"})
    assert roles == []
