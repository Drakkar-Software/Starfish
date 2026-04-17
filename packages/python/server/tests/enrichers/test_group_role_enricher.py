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


def _write_members_doc(
    store: MemoryObjectStore,
    key: str,
    members: list[str],
    extra: dict | None = None,
) -> None:
    """Write a minimal StoredDocument so the enricher can read it."""
    data: dict = {"members": members}
    if extra:
        data.update(extra)
    doc = {
        "v": 1,
        "data": data,
        "timestamps": {"members": 1000},
        "hash": "test-hash",
    }
    # We need to store it synchronously; use the internal dict directly.
    store._data[key] = json.dumps(doc)


def _write_candidacy_doc(
    store: MemoryObjectStore,
    key: str,
    status: str,
    message: str | None = None,
) -> None:
    """Write a minimal candidacy StoredDocument."""
    data: dict = {"status": status}
    if message is not None:
        data["message"] = message
    store._data[key] = json.dumps({"v": 1, "data": data, "timestamps": {}, "hash": "h"})


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


# ── Additional coverage ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_non_member_push_denied():
    app, store = _build_integration_app("charlie")

    members_doc = {"v": 1, "data": {"members": ["alice", "bob"]}, "timestamps": {"members": 1000}, "hash": "h"}
    store._data["groups/group-1/members"] = json.dumps(members_doc)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/chats/group-1/2026-04-14",
            json={"data": {"messages": []}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_user_gains_access_after_add():
    store = MemoryObjectStore()
    # Start: charlie is NOT a member
    _write_members_doc(store, "groups/group-1/members", ["alice"])

    # Write a chat doc for charlie to eventually read
    chat_doc = {"v": 1, "data": {"messages": []}, "timestamps": {"messages": 1000}, "hash": "h"}
    store._data["chats/group-1/2026-04-14"] = json.dumps(chat_doc)

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
        cache_ttl_ms=0,  # no cache — membership changes take effect immediately
    ))
    config = SyncConfig(version=1, collections=[chat_col, members_col])

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="charlie", roles=[])

    router = create_sync_router(SyncRouterOptions(
        store=store, config=config, role_resolver=role_resolver, role_enricher=enricher,
    ))
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Charlie is not yet a member — pull denied
        resp = await client.get("/pull/chats/group-1/2026-04-14")
        assert resp.status_code == 403

        # Admin adds charlie to the members doc
        _write_members_doc(store, "groups/group-1/members", ["alice", "charlie"])

        # Charlie now has access (cache disabled, enricher re-reads immediately)
        resp = await client.get("/pull/chats/group-1/2026-04-14")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_user_loses_access_after_remove():
    store = MemoryObjectStore()
    # Start: alice IS a member
    _write_members_doc(store, "groups/group-1/members", ["alice", "bob"])

    chat_doc = {"v": 1, "data": {"messages": []}, "timestamps": {"messages": 1000}, "hash": "h"}
    store._data["chats/group-1/2026-04-14"] = json.dumps(chat_doc)

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
        cache_ttl_ms=0,  # no cache — membership changes take effect immediately
    ))
    config = SyncConfig(version=1, collections=[chat_col, members_col])

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="alice", roles=[])

    router = create_sync_router(SyncRouterOptions(
        store=store, config=config, role_resolver=role_resolver, role_enricher=enricher,
    ))
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Alice is a member — pull succeeds
        resp = await client.get("/pull/chats/group-1/2026-04-14")
        assert resp.status_code == 200

        # Admin removes alice from the members doc
        _write_members_doc(store, "groups/group-1/members", ["bob"])

        # Alice can no longer pull (cache is disabled)
        resp = await client.get("/pull/chats/group-1/2026-04-14")
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_cache_expires_and_rereads():
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
        cache_ttl_ms=5_000,
    ))

    # Simulate time advancing: 0s → 4.999s → 5.001s
    # time.monotonic() returns seconds; enricher multiplies by 1000 for ms comparison
    with patch("time.monotonic", side_effect=[0.0, 4.999, 5.001]):
        # Call 1: reads from store, populates cache
        await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
        assert call_count == 1

        # Call 2: within TTL (4999 ms < 5000 ms) — served from cache
        await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
        assert call_count == 1

        # Call 3: TTL elapsed (5001 ms > 5000 ms) — re-reads from store
        await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
        assert call_count == 2


# ── Candidacy unit tests ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_candidacy_disabled_globally_when_no_path():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", ["alice"], {"candidacyEnabled": True})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending")

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        # no candidacy_path — feature disabled globally
    ))

    roles = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles == []


@pytest.mark.asyncio
async def test_candidacy_disabled_per_group_when_false():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", ["alice"], {"candidacyEnabled": False})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending")

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
    ))

    roles = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles == []


@pytest.mark.asyncio
async def test_candidacy_disabled_per_group_when_absent():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", ["alice"])
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending")

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
    ))

    roles = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles == []


@pytest.mark.asyncio
async def test_pending_candidacy_grants_candidate_role():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", ["alice"], {"candidacyEnabled": True})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending", "Please let me in")

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
    ))

    roles = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles == ["group-candidate"]


@pytest.mark.asyncio
async def test_member_with_candidacy_enabled_gets_member_role():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", ["alice"], {"candidacyEnabled": True})
    _write_candidacy_doc(store, "groups/group-1/candidacies/alice", "pending")

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
    ))

    roles = await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
    assert roles == ["group-member"]


@pytest.mark.asyncio
async def test_accepted_candidacy_no_role():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", ["alice"], {"candidacyEnabled": True})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "accepted")

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
    ))

    roles = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles == []


@pytest.mark.asyncio
async def test_denied_candidacy_no_role():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", ["alice"], {"candidacyEnabled": True})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "denied")

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
    ))

    roles = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles == []


@pytest.mark.asyncio
async def test_no_candidacy_doc_no_role():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", ["alice"], {"candidacyEnabled": True})
    # no candidacy doc

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
    ))

    roles = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles == []


@pytest.mark.asyncio
async def test_custom_candidacy_role():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", [], {"candidacyEnabled": True})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending")

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
        candidacy_role="applicant",
    ))

    roles = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles == ["applicant"]


@pytest.mark.asyncio
async def test_custom_candidacy_status_field():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", [], {"candidacyEnabled": True})
    store._data["groups/group-1/candidacies/charlie"] = json.dumps(
        {"v": 1, "data": {"state": "pending"}, "timestamps": {}, "hash": "h"}
    )

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
        candidacy_status_field="state",
    ))

    roles = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles == ["group-candidate"]


@pytest.mark.asyncio
async def test_custom_candidacy_enabled_field():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", [], {"openToApplications": True})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending")

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
        candidacy_enabled_field="openToApplications",
    ))

    roles = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles == ["group-candidate"]


@pytest.mark.asyncio
async def test_candidacy_caches_lookups():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", [], {"candidacyEnabled": True})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending")

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
        candidacy_path="groups/{groupId}/candidacies/{identity}",
        cache_ttl_ms=60_000,
    ))

    await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})

    # 1 read for members doc + 1 read for candidacy doc (second call from cache)
    assert call_count == 2


@pytest.mark.asyncio
async def test_candidacy_cache_ttl_zero_disables_caching():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", [], {"candidacyEnabled": True})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending")

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
        candidacy_path="groups/{groupId}/candidacies/{identity}",
        cache_ttl_ms=60_000,
        candidacy_cache_ttl_ms=0,
    ))

    await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})

    # members cached (1 read), candidacy not cached (2 reads)
    assert call_count == 3


@pytest.mark.asyncio
async def test_corrupt_candidacy_doc_no_role():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", [], {"candidacyEnabled": True})
    store._data["groups/group-1/candidacies/charlie"] = "not valid json{{"

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
    ))

    roles = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles == []


# ── Candidacy integration tests ───────────────────────────────────────────────

def _build_candidacy_integration_app(identity: str = "charlie"):
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
    candidacy_col = CollectionConfig(
        name="candidacy",
        storagePath="groups/{groupId}/candidacies/{identity}",
        readRoles=["group-admin", "self"],
        writeRoles=["group-admin", "self"],
        encryption="none",
        maxBodyBytes=4096,
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
        candidacy_path="groups/{groupId}/candidacies/{identity}",
        cache_ttl_ms=0,  # no cache — changes take effect immediately
    ))

    config = SyncConfig(version=1, collections=[chat_col, candidacy_col, members_col])

    async def role_resolver(request) -> AuthResult:
        return AuthResult(identity=identity, roles=[])

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
async def test_pending_candidate_cannot_access_member_only_collection():
    app, store = _build_candidacy_integration_app("charlie")

    _write_members_doc(store, "groups/group-1/members", ["alice"], {"candidacyEnabled": True})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending", "Let me in!")

    chat_doc = {"v": 1, "data": {"messages": []}, "timestamps": {}, "hash": "h"}
    store._data["chats/group-1/2026-04-17"] = json.dumps(chat_doc)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/chats/group-1/2026-04-17")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_candidate_can_push_own_candidacy_via_self():
    app, store = _build_candidacy_integration_app("charlie")

    _write_members_doc(store, "groups/group-1/members", ["alice"], {"candidacyEnabled": True})

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/groups/group-1/candidacies/charlie",
            json={"data": {"status": "pending", "message": "I'd like to join"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_accepted_candidate_added_to_members_gains_access():
    app, store = _build_candidacy_integration_app("charlie")

    _write_members_doc(store, "groups/group-1/members", ["alice"], {"candidacyEnabled": True})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "accepted")

    chat_doc = {"v": 1, "data": {"messages": []}, "timestamps": {}, "hash": "h"}
    store._data["chats/group-1/2026-04-17"] = json.dumps(chat_doc)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Accepted but not yet in members — no access
        resp = await client.get("/pull/chats/group-1/2026-04-17")
        assert resp.status_code == 403

        # Admin adds charlie to members doc
        _write_members_doc(store, "groups/group-1/members", ["alice", "charlie"], {"candidacyEnabled": True})

        # Now charlie has group-member role
        resp = await client.get("/pull/chats/group-1/2026-04-17")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_per_group_toggle_disables_candidacy():
    app, store = _build_candidacy_integration_app("charlie")

    # group-1: candidacy enabled; group-2: disabled
    _write_members_doc(store, "groups/group-1/members", ["alice"], {"candidacyEnabled": True})
    _write_members_doc(store, "groups/group-2/members", ["alice"], {"candidacyEnabled": False})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending")
    _write_candidacy_doc(store, "groups/group-2/candidacies/charlie", "pending")

    chat_doc = {"v": 1, "data": {"messages": []}, "timestamps": {}, "hash": "h"}
    store._data["chats/group-1/2026-04-17"] = json.dumps(chat_doc)
    store._data["chats/group-2/2026-04-17"] = json.dumps(chat_doc)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # group-1: candidacy enabled but charlie is candidate not member — 403
        resp = await client.get("/pull/chats/group-1/2026-04-17")
        assert resp.status_code == 403

        # group-2: candidacy disabled — 403 regardless
        resp = await client.get("/pull/chats/group-2/2026-04-17")
        assert resp.status_code == 403


# ── Regression: correctness and security ──────────────────────────────────────

# Issue #1: wrong identity substitution

@pytest.mark.asyncio
async def test_does_not_use_url_identity_param_for_candidacy_lookup():
    """Auth user with no candidacy doc must not inherit pending status from URL target user."""
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", [], {"candidacyEnabled": True})
    # charlie (URL identity) has a pending doc; admin (auth user) has none
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending")

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
        cache_ttl_ms=0,
    ))

    # admin is auth'd; {identity: "charlie"} comes from URL params
    roles = await enricher(
        AuthResult(identity="admin", roles=[]),
        {"groupId": "group-1", "identity": "charlie"},
    )
    assert roles == []


@pytest.mark.asyncio
async def test_uses_auth_identity_when_url_identity_has_denied_status():
    """Auth user with pending candidacy must get group-candidate even when URL identity is denied."""
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", [], {"candidacyEnabled": True})
    # charlie (URL identity) is denied; dave (auth user) is pending
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "denied")
    _write_candidacy_doc(store, "groups/group-1/candidacies/dave", "pending")

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
        cache_ttl_ms=0,
    ))

    roles = await enricher(
        AuthResult(identity="dave", roles=[]),
        {"groupId": "group-1", "identity": "charlie"},
    )
    assert roles == ["group-candidate"]


# Issue #2: Python already logs; these are regression tests to verify it stays that way

@pytest.mark.asyncio
async def test_logs_on_corrupt_members_document():
    store = MemoryObjectStore()
    store._data["groups/group-1/members"] = "not valid json{{"

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
    ))

    with patch("starfish_server.enrichers.group_role_enricher.logging") as mock_log:
        mock_logger = mock_log.getLogger.return_value
        await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
        mock_logger.error.assert_called()


@pytest.mark.asyncio
async def test_logs_on_corrupt_candidacy_document():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", [], {"candidacyEnabled": True})
    store._data["groups/group-1/candidacies/charlie"] = "not valid json{{"

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
    ))

    with patch("starfish_server.enrichers.group_role_enricher.logging") as mock_log:
        mock_logger = mock_log.getLogger.return_value
        await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
        mock_logger.error.assert_called()


# Issue #3: corrupt docs must not poison cache

@pytest.mark.asyncio
async def test_corrupt_members_doc_not_cached():
    store = MemoryObjectStore()
    store._data["groups/group-1/members"] = "not valid json{{"

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

    # First call: corrupt doc → empty membership
    roles1 = await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
    assert roles1 == []
    assert call_count == 1

    # Fix the document
    _write_members_doc(store, "groups/group-1/members", ["alice"])

    # Second call within TTL — must NOT serve stale corrupt result from cache
    roles2 = await enricher(AuthResult(identity="alice", roles=[]), {"groupId": "group-1"})
    assert roles2 == ["group-member"]
    assert call_count == 2


@pytest.mark.asyncio
async def test_corrupt_candidacy_doc_not_cached():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", [], {"candidacyEnabled": True})
    store._data["groups/group-1/candidacies/charlie"] = "not valid json{{"

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
        cache_ttl_ms=60_000,
    ))

    # First call: corrupt → no candidacy role
    roles1 = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles1 == []

    # Fix the document
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending")

    # Second call within TTL — must NOT serve stale corrupt null from cache
    roles2 = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles2 == ["group-candidate"]


@pytest.mark.asyncio
async def test_null_candidacy_doc_not_cached():
    """Missing (null) candidacy doc must not be cached — user can apply after first check."""
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", [], {"candidacyEnabled": True})
    # No candidacy doc written yet

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
        cache_ttl_ms=60_000,
    ))

    # First call: doc absent → no candidacy role
    roles1 = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles1 == []

    # Charlie submits application
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending")

    # Second call within TTL — must NOT serve stale null from cache
    roles2 = await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
    assert roles2 == ["group-candidate"]


# Issue #4: construction-time validation

def test_raises_when_members_path_missing_group_param():
    with pytest.raises(Exception, match="groupId"):
        create_group_role_enricher(GroupRoleEnricherOptions(
            store=MemoryObjectStore(),
            members_path="groups/members",
            group_param="groupId",
        ))


def test_raises_on_empty_candidacy_path():
    with pytest.raises(Exception):
        create_group_role_enricher(GroupRoleEnricherOptions(
            store=MemoryObjectStore(),
            members_path="groups/{groupId}/members",
            group_param="groupId",
            candidacy_path="",
        ))


def test_raises_when_candidacy_path_missing_identity():
    with pytest.raises(Exception, match="identity"):
        create_group_role_enricher(GroupRoleEnricherOptions(
            store=MemoryObjectStore(),
            members_path="groups/{groupId}/members",
            group_param="groupId",
            candidacy_path="groups/{groupId}/candidacies/fixed",
        ))


def test_raises_when_candidacy_path_missing_group_param():
    with pytest.raises(Exception, match="groupId"):
        create_group_role_enricher(GroupRoleEnricherOptions(
            store=MemoryObjectStore(),
            members_path="groups/{groupId}/members",
            group_param="groupId",
            candidacy_path="candidacies/{identity}",
        ))


# Issue #5: candidacy cache TTL expiry

@pytest.mark.asyncio
async def test_candidacy_cache_ttl_expiry_while_members_cache_stays_warm():
    store = MemoryObjectStore()
    _write_members_doc(store, "groups/group-1/members", [], {"candidacyEnabled": True})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending")

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
        candidacy_path="groups/{groupId}/candidacies/{identity}",
        cache_ttl_ms=60_000,        # long members TTL
        candidacy_cache_ttl_ms=5_000,  # short candidacy TTL
    ))

    # time.monotonic() is called once per resolve function per enricher call
    # Call 1: members(0ms) + candidacy(0ms) → both cached
    # Call 2: members(4999ms<60000) hit + candidacy(4999ms<5000) hit → no reads
    # Call 3: members(5001ms<60000) hit + candidacy(5001ms>5000) miss → 1 read
    with patch("time.monotonic", side_effect=[0.0, 0.0, 4.999, 4.999, 5.001, 5.001]):
        await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
        assert call_count == 2

        await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
        assert call_count == 2

        await enricher(AuthResult(identity="charlie", roles=[]), {"groupId": "group-1"})
        assert call_count == 3


# Issue #6: group-candidate as access-granting role

@pytest.mark.asyncio
async def test_pending_candidate_gets_200_on_candidate_gated_collection():
    store = MemoryObjectStore()

    info_col = CollectionConfig(
        name="group-info",
        storagePath="groups/{groupId}/info",
        readRoles=["group-candidate", "group-member"],
        writeRoles=["group-admin"],
        encryption="none",
        maxBodyBytes=4096,
    )
    candidacy_col = CollectionConfig(
        name="candidacy",
        storagePath="groups/{groupId}/candidacies/{identity}",
        readRoles=["group-admin", "self"],
        writeRoles=["group-admin", "self"],
        encryption="none",
        maxBodyBytes=4096,
    )
    members_col = CollectionConfig(
        name="group-members",
        storagePath="groups/{groupId}/members",
        readRoles=["group-admin"],
        writeRoles=["group-admin"],
        encryption="none",
        maxBodyBytes=65536,
    )

    _write_members_doc(store, "groups/group-1/members", ["alice"], {"candidacyEnabled": True})
    _write_candidacy_doc(store, "groups/group-1/candidacies/charlie", "pending")
    store._data["groups/group-1/info"] = json.dumps(
        {"v": 1, "data": {"welcome": "hello"}, "timestamps": {}, "hash": "h"}
    )

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
        cache_ttl_ms=0,
    ))
    config = SyncConfig(version=1, collections=[info_col, candidacy_col, members_col])

    async def charlie_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="charlie", roles=[])

    router = create_sync_router(SyncRouterOptions(
        store=store, config=config, role_resolver=charlie_resolver, role_enricher=enricher,
    ))
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # charlie (pending) can read group info
        resp = await client.get("/pull/groups/group-1/info")
        assert resp.status_code == 200

    # dave (no candidacy doc) cannot read group info
    async def dave_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="dave", roles=[])

    router2 = create_sync_router(SyncRouterOptions(
        store=store, config=config, role_resolver=dave_resolver, role_enricher=enricher,
    ))
    app2 = FastAPI()
    app2.include_router(router2)

    async with AsyncClient(transport=ASGITransport(app=app2), base_url="http://test") as client:
        resp = await client.get("/pull/groups/group-1/info")
        assert resp.status_code == 403


# Issue #8: cache key collision

@pytest.mark.asyncio
async def test_no_candidacy_cache_collision_when_groupid_or_identity_contains_colon():
    store = MemoryObjectStore()
    # groupId="a:b", identity="c" → has a pending candidacy doc
    _write_members_doc(store, "groups/a:b/members", [], {"candidacyEnabled": True})
    _write_candidacy_doc(store, "groups/a:b/candidacies/c", "pending")
    # groupId="a", identity="b:c" → NO candidacy doc
    _write_members_doc(store, "groups/a/members", [], {"candidacyEnabled": True})

    enricher = create_group_role_enricher(GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
        candidacy_path="groups/{groupId}/candidacies/{identity}",
        cache_ttl_ms=60_000,
    ))

    # "a:b" + "c" → pending → group-candidate (cached)
    roles1 = await enricher(AuthResult(identity="c", roles=[]), {"groupId": "a:b"})
    assert roles1 == ["group-candidate"]

    # "a" + "b:c" → no doc → must NOT collide with cached "a:b" + "c"
    roles2 = await enricher(AuthResult(identity="b:c", roles=[]), {"groupId": "a"})
    assert roles2 == []
