"""Tests for create_entitlement_role_enricher and compose_enrichers."""

import json
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.enrichers.entitlement_role_enricher import (
    EntitlementRoleEnricherOptions,
    create_entitlement_role_enricher,
)
from starfish_server.enrichers.group_role_enricher import (
    GroupRoleEnricherOptions,
    create_group_role_enricher,
)
from starfish_server.enrichers.compose import compose_enrichers
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from tests.helpers import MemoryObjectStore


def _write_entitlement_doc(store: MemoryObjectStore, key: str, features: list[str]) -> None:
    """Write a minimal StoredDocument so the enricher can read it."""
    doc = {
        "v": 1,
        "data": {"features": features},
        "timestamps": {"features": 1000},
        "hash": "test-hash",
    }
    store._data[key] = json.dumps(doc)


# ── Unit tests ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_grants_roles_for_all_slugs():
    store = MemoryObjectStore()
    _write_entitlement_doc(store, "users/alice/entitlements", ["premium-package-1", "paid-cloud-sync"])

    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store))

    roles = await enricher(AuthResult(identity="alice", roles=[]), {})
    assert sorted(roles) == ["entitlement:paid-cloud-sync", "entitlement:premium-package-1"]


@pytest.mark.asyncio
async def test_returns_empty_when_document_missing():
    store = MemoryObjectStore()
    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store))

    roles = await enricher(AuthResult(identity="alice", roles=[]), {})
    assert roles == []


@pytest.mark.asyncio
async def test_returns_empty_when_document_corrupt():
    store = MemoryObjectStore()
    store._data["users/alice/entitlements"] = "not valid json{{"

    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store))
    roles = await enricher(AuthResult(identity="alice", roles=[]), {})
    assert roles == []


@pytest.mark.asyncio
async def test_returns_empty_when_field_not_a_list():
    store = MemoryObjectStore()
    doc = {"v": 1, "data": {"features": "not-a-list"}, "timestamps": {}, "hash": "h"}
    store._data["users/alice/entitlements"] = json.dumps(doc)

    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store))
    roles = await enricher(AuthResult(identity="alice", roles=[]), {})
    assert roles == []


@pytest.mark.asyncio
async def test_filters_non_string_elements():
    store = MemoryObjectStore()
    doc = {"v": 1, "data": {"features": ["valid-feature", 42, None, True]}, "timestamps": {}, "hash": "h"}
    store._data["users/alice/entitlements"] = json.dumps(doc)

    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store))
    roles = await enricher(AuthResult(identity="alice", roles=[]), {})
    assert roles == ["entitlement:valid-feature"]


@pytest.mark.asyncio
async def test_custom_field():
    store = MemoryObjectStore()
    doc = {"v": 1, "data": {"entitlements": ["pro"]}, "timestamps": {}, "hash": "h"}
    store._data["users/alice/entitlements"] = json.dumps(doc)

    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(
        store=store, field="entitlements",
    ))
    roles = await enricher(AuthResult(identity="alice", roles=[]), {})
    assert roles == ["entitlement:pro"]


@pytest.mark.asyncio
async def test_custom_role_prefix():
    store = MemoryObjectStore()
    _write_entitlement_doc(store, "users/alice/entitlements", ["premium"])

    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(
        store=store, role_prefix="feat",
    ))
    roles = await enricher(AuthResult(identity="alice", roles=[]), {})
    assert roles == ["feat:premium"]


@pytest.mark.asyncio
async def test_custom_path_template():
    store = MemoryObjectStore()
    doc = {"v": 1, "data": {"features": ["pro"]}, "timestamps": {}, "hash": "h"}
    store._data["ents/alice"] = json.dumps(doc)

    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(
        store=store, path="ents/{identity}",
    ))
    roles = await enricher(AuthResult(identity="alice", roles=[]), {})
    assert roles == ["entitlement:pro"]


@pytest.mark.asyncio
async def test_uses_identity_ignores_url_params():
    store = MemoryObjectStore()
    _write_entitlement_doc(store, "users/alice/entitlements", ["premium"])

    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store))
    roles = await enricher(
        AuthResult(identity="alice", roles=[]),
        {"groupId": "group-42", "someOther": "value"},
    )
    assert roles == ["entitlement:premium"]


@pytest.mark.asyncio
async def test_caches_lookups_within_ttl():
    store = MemoryObjectStore()
    _write_entitlement_doc(store, "users/alice/entitlements", ["premium"])

    call_count = 0
    original_get_string = store.get_string

    async def counting_get_string(key: str) -> str | None:
        nonlocal call_count
        call_count += 1
        return await original_get_string(key)

    store.get_string = counting_get_string

    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(
        store=store, cache_ttl_ms=60_000,
    ))

    await enricher(AuthResult(identity="alice", roles=[]), {})
    await enricher(AuthResult(identity="alice", roles=[]), {})

    assert call_count == 1


@pytest.mark.asyncio
async def test_separate_cache_entries_per_identity():
    store = MemoryObjectStore()
    _write_entitlement_doc(store, "users/alice/entitlements", ["premium"])
    _write_entitlement_doc(store, "users/bob/entitlements", ["basic"])

    call_count = 0
    original_get_string = store.get_string

    async def counting_get_string(key: str) -> str | None:
        nonlocal call_count
        call_count += 1
        return await original_get_string(key)

    store.get_string = counting_get_string

    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(
        store=store, cache_ttl_ms=60_000,
    ))

    await enricher(AuthResult(identity="alice", roles=[]), {})
    await enricher(AuthResult(identity="bob", roles=[]), {})
    await enricher(AuthResult(identity="alice", roles=[]), {})  # from cache
    await enricher(AuthResult(identity="bob", roles=[]), {})    # from cache

    assert call_count == 2


@pytest.mark.asyncio
async def test_no_cache_when_ttl_zero():
    store = MemoryObjectStore()
    _write_entitlement_doc(store, "users/alice/entitlements", ["premium"])

    call_count = 0
    original_get_string = store.get_string

    async def counting_get_string(key: str) -> str | None:
        nonlocal call_count
        call_count += 1
        return await original_get_string(key)

    store.get_string = counting_get_string

    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(
        store=store, cache_ttl_ms=0,
    ))

    await enricher(AuthResult(identity="alice", roles=[]), {})
    await enricher(AuthResult(identity="alice", roles=[]), {})

    assert call_count == 2


@pytest.mark.asyncio
async def test_cache_expires_and_rereads():
    store = MemoryObjectStore()
    _write_entitlement_doc(store, "users/alice/entitlements", ["premium"])

    call_count = 0
    original_get_string = store.get_string

    async def counting_get_string(key: str) -> str | None:
        nonlocal call_count
        call_count += 1
        return await original_get_string(key)

    store.get_string = counting_get_string

    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(
        store=store, cache_ttl_ms=5_000,
    ))

    # time.monotonic() returns seconds; enricher multiplies by 1000 for ms comparison
    with patch("time.monotonic", side_effect=[0.0, 4.999, 5.001]):
        # Call 1 at t=0 — reads from store
        await enricher(AuthResult(identity="alice", roles=[]), {})
        assert call_count == 1

        # Call 2 at t=4.999s — within TTL, served from cache
        await enricher(AuthResult(identity="alice", roles=[]), {})
        assert call_count == 1

        # Call 3 at t=5.001s — TTL elapsed, re-reads
        await enricher(AuthResult(identity="alice", roles=[]), {})
        assert call_count == 2


# ── compose_enrichers unit tests ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_compose_merges_roles_from_multiple_enrichers():
    store = MemoryObjectStore()
    _write_entitlement_doc(store, "users/alice/entitlements", ["premium"])

    members_doc = {"v": 1, "data": {"members": ["alice"]}, "timestamps": {"members": 1000}, "hash": "h"}
    store._data["groups/g1/members"] = json.dumps(members_doc)

    group_enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store, members_path="groups/{groupId}/members", group_param="groupId",
    ))
    entitlement_enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store))

    composed = compose_enrichers(group_enricher, entitlement_enricher)
    roles = await composed(AuthResult(identity="alice", roles=[]), {"groupId": "g1"})

    assert "group-member" in roles
    assert "entitlement:premium" in roles


@pytest.mark.asyncio
async def test_compose_empty_returns_empty():
    composed = compose_enrichers()
    roles = await composed(AuthResult(identity="alice", roles=[]), {})
    assert roles == []


# ── Integration tests through the router ─────────────────────────────────────

def _build_integration_app(identity: str = "alice", base_roles: list[str] | None = None):
    if base_roles is None:
        base_roles = []

    store = MemoryObjectStore()

    entitlements_col = CollectionConfig(
        name="entitlements",
        storagePath="users/{identity}/entitlements",
        readRoles=["self"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=4096,
    )
    premium_col = CollectionConfig(
        name="premium-data",
        storagePath="premium/{resource}",
        readRoles=["entitlement:premium-package-1"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
    )

    enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store))
    config = SyncConfig(version=1, collections=[entitlements_col, premium_col])

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=base_roles)

    router = create_sync_router(SyncRouterOptions(
        store=store,
        config=config,
        role_resolver=role_resolver,
        role_enricher=enricher,
    ))
    app = FastAPI()
    app.include_router(router)
    return app, store


@pytest.mark.asyncio
async def test_user_with_entitlement_can_pull():
    app, store = _build_integration_app("alice")

    _write_entitlement_doc(store, "users/alice/entitlements", ["premium-package-1"])
    premium_doc = {"v": 1, "data": {"content": "secret data"}, "timestamps": {"content": 1000}, "hash": "h"}
    store._data["premium/article-1"] = json.dumps(premium_doc)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/premium/article-1")
    assert resp.status_code == 200
    assert resp.json()["data"]["content"] == "secret data"


@pytest.mark.asyncio
async def test_user_without_entitlement_gets_403():
    app, store = _build_integration_app("alice")
    _write_entitlement_doc(store, "users/alice/entitlements", ["basic-tier"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/premium/article-1")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_user_with_no_entitlement_doc_gets_403():
    app, _ = _build_integration_app("alice")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/premium/article-1")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_user_can_read_own_entitlement_doc():
    app, store = _build_integration_app("alice")
    _write_entitlement_doc(store, "users/alice/entitlements", ["premium-package-1"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/users/alice/entitlements")
    assert resp.status_code == 200
    assert "premium-package-1" in resp.json()["data"]["features"]


@pytest.mark.asyncio
async def test_compose_enrichers_group_and_entitlement():
    store = MemoryObjectStore()

    members_doc = {"v": 1, "data": {"members": ["alice"]}, "timestamps": {"members": 1000}, "hash": "h"}
    store._data["groups/g1/members"] = json.dumps(members_doc)
    _write_entitlement_doc(store, "users/alice/entitlements", ["premium-package-1"])

    col = CollectionConfig(
        name="combined",
        storagePath="combined/{groupId}/{resource}",
        readRoles=["group-member", "entitlement:premium-package-1"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
    )
    doc = {"v": 1, "data": {"x": 1}, "timestamps": {"x": 1000}, "hash": "h"}
    store._data["combined/g1/thing"] = json.dumps(doc)

    config = SyncConfig(version=1, collections=[col])

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="alice", roles=[])

    router = create_sync_router(SyncRouterOptions(
        store=store,
        config=config,
        role_resolver=role_resolver,
        role_enricher=compose_enrichers(
            create_group_role_enricher(GroupRoleEnricherOptions(
                store=store, members_path="groups/{groupId}/members", group_param="groupId",
            )),
            create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store)),
        ),
    ))
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/combined/g1/thing")
    assert resp.status_code == 200
