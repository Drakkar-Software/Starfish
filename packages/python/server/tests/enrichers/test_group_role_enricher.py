"""Tests for create_group_role_enricher."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.enrichers.group_role_enricher import (
    GroupRoleEnricherOptions,
    create_group_role_enricher,
)
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from tests.helpers import MemoryObjectStore


def _write_members_doc(store: MemoryObjectStore, key: str, members: list[str]) -> None:
    """Write a minimal StoredDocument so the enricher can read it."""
    doc = {
        "v": 1,
        "data": {"members": members},
        "timestamps": {"members": 1000},
        "hash": "test-hash",
    }
    # We need to store it synchronously; use the internal dict directly.
    store._data[key] = json.dumps(doc)


# ── Unit tests ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_grants_role_to_member():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", ["alice", "bob"])

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
    ))

    roles = await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
    assert roles == ["group-member"]


@pytest.mark.asyncio
async def test_no_role_for_non_member():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", ["alice", "bob"])

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
    ))

    roles = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles == []


@pytest.mark.asyncio
async def test_no_role_when_group_param_absent():
    store = MemoryObjectStore()
    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
    ))
    roles = await enricher(AuthResult(identity="alice", roles=[]), {})
    assert roles == []


@pytest.mark.asyncio
async def test_no_role_when_document_missing():
    store = MemoryObjectStore()
    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
    ))
    roles = await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "nonexistent"})
    assert roles == []


@pytest.mark.asyncio
async def test_custom_members_field():
    store = MemoryObjectStore()
    doc = {"v": 1, "data": {"participants": ["alice"]}, "timestamps": {}, "hash": "h"}
    store._data["groups/group-1/members"] = json.dumps(doc)

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        members_field="participants",
    ))
    roles = await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
    assert roles == ["group-member"]


@pytest.mark.asyncio
async def test_custom_role():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", ["alice"])

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        role="chat-member",
    ))
    roles = await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
    assert roles == ["chat-member"]


@pytest.mark.asyncio
async def test_caches_membership():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", ["alice"])

    call_count = 0
    original_get_string = store.get_string

    async def counting_get_string(key: str) -> str | None:
        nonlocal call_count
        call_count += 1
        return await original_get_string(key)

    store.get_string = counting_get_string

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        cache_ttl_ms=60_000,
    ))

    await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
    await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
    await enricher(AuthResult(identity="bob", roles=[]), {"groupId": "group-1"})

    # Only 1 store read — second and third served from cache
    assert call_count == 1


@pytest.mark.asyncio
async def test_no_cache_when_ttl_is_zero():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", ["alice"])

    call_count = 0
    original_get_string = store.get_string

    async def counting_get_string(key: str) -> str | None:
        nonlocal call_count
        call_count += 1
        return await original_get_string(key)

    store.get_string = counting_get_string

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        cache_ttl_ms=0,
    ))

    await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
    await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})

    assert call_count == 2


@pytest.mark.asyncio
async def test_handles_corrupt_document():
    store = MemoryObjectStore()
    store._data["groups/group-1/members"] = "not valid json{{"

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
    ))
    roles = await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
    assert roles == []


@pytest.mark.asyncio
async def test_handles_non_list_members_field():
    store = MemoryObjectStore()
    doc = {"v": 1, "data": {"members": "alice"}, "timestamps": {}, "hash": "h"}
    store._data["groups/group-1/members"] = json.dumps(doc)

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
    ))
    roles = await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
    assert roles == []


# ── Integration tests through the router ─────────────────────────────────────

def _build_integration_app(identity: str = "alice", base_roles: list[str] | None = None):
    if base_roles is None:
        base_roles = []

    store = MemoryObjectStore()

    chat_col = CollectionConfig(
        name="chat",
        storagePath="chats/{groupId}/{day}",
        readRoles=["group-member"],
        writeRoles=["group-member"],
        encryption="none",
        maxBodyBytes=65536,
        listable=True,
    )
    members_col = CollectionConfig(
        name="group-members",
        storagePath="groups/{groupId}/members",
        readRoles=["group-admin"],
        writeRoles=["group-admin"],
        encryption="none",
        maxBodyBytes=65536,
    )

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
    ))

    config = SyncConfig(version=1, collections=[chat_col, members_col])

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
async def test_member_can_pull():
    app, store = _build_integration_app("alice")

    members_doc = {"v": 1, "data": {"members": ["alice", "bob"]}, "timestamps": {"members": 1000}, "hash": "h"}
    store._data["groups/group-1/members"] = json.dumps(members_doc)

    chat_doc = {"v": 1, "data": {"messages": [{"text": "hi"}]}, "timestamps": {"messages": 1000}, "hash": "h"}
    store._data["chats/group-1/2026-04-13"] = json.dumps(chat_doc)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/chats/group-1/2026-04-13")
    assert resp.status_code == 200
    assert resp.json()["data"]["messages"] is not None


@pytest.mark.asyncio
async def test_non_member_gets_403():
    app, store = _build_integration_app("charlie")

    members_doc = {"v": 1, "data": {"members": ["alice", "bob"]}, "timestamps": {"members": 1000}, "hash": "h"}
    store._data["groups/group-1/members"] = json.dumps(members_doc)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/chats/group-1/2026-04-13")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_member_can_push():
    app, store = _build_integration_app("alice")

    members_doc = {"v": 1, "data": {"members": ["alice"]}, "timestamps": {"members": 1000}, "hash": "h"}
    store._data["groups/group-1/members"] = json.dumps(members_doc)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/chats/group-1/2026-04-13",
            json={"data": {"messages": []}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_member_can_list_days():
    app, store = _build_integration_app("alice")

    members_doc = {"v": 1, "data": {"members": ["alice"]}, "timestamps": {"members": 1000}, "hash": "h"}
    store._data["groups/group-1/members"] = json.dumps(members_doc)

    for day in ["2026-04-12", "2026-04-13"]:
        chat_doc = {"v": 1, "data": {"messages": []}, "timestamps": {"messages": 1000}, "hash": "h"}
        store._data[f"chats/group-1/{day}"] = json.dumps(chat_doc)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/list/chats/group-1")
    assert resp.status_code == 200
    assert sorted(resp.json()["items"]) == ["2026-04-12", "2026-04-13"]


@pytest.mark.asyncio
async def test_non_member_cannot_list():
    app, store = _build_integration_app("charlie")

    members_doc = {"v": 1, "data": {"members": ["alice"]}, "timestamps": {"members": 1000}, "hash": "h"}
    store._data["groups/group-1/members"] = json.dumps(members_doc)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/list/chats/group-1")
    assert resp.status_code == 403
