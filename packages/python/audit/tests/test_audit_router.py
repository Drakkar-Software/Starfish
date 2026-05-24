"""AuditLogger must be called on push operations in the Python router.
This test suite verifies that
SyncRouterOptions.audit_logger is wired through the push handler.
"""

import asyncio

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.router.route_builder import create_sync_router, SyncRouterOptions, AuthResult
from starfish_audit import AuditLogger, AuditEntry
from tests.helpers import MemoryObjectStore


def _make_app_with_audit(audit_logger: AuditLogger) -> tuple[FastAPI, MemoryObjectStore]:
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="settings",
                storagePath="users/{identity}/settings",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["self"])

    router = create_sync_router(
        SyncRouterOptions(
            store=store,
            config=config,
            role_resolver=role_resolver,
            audit_logger=audit_logger,
        ),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


# ─── successful push emits audit entry ──────────────────────────────────

@pytest.mark.asyncio
async def test_successful_push_records_audit_entry():
    """A 200 push must call audit_logger.record with success=True."""
    recorded: list[AuditEntry] = []

    class CapturingLogger(AuditLogger):
        async def record(self, entry: AuditEntry) -> None:
            recorded.append(entry)

    app, _ = _make_app_with_audit(CapturingLogger())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"x": 1}, "baseHash": None},
        )

    assert resp.status_code == 200
    assert len(recorded) == 1
    entry = recorded[0]
    assert entry.action == "push"
    assert entry.success is True
    assert entry.status_code == 200
    assert entry.collection == "settings"
    assert entry.identity == "user-1"


# ─── conflict (409) push emits audit entry with failure ─────────────────

@pytest.mark.asyncio
async def test_conflict_push_records_audit_entry():
    """ A 409 conflict push must call audit_logger.record with success=False."""
    recorded: list[AuditEntry] = []

    class CapturingLogger(AuditLogger):
        async def record(self, entry: AuditEntry) -> None:
            recorded.append(entry)

    app, _ = _make_app_with_audit(CapturingLogger())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # First push succeeds
        await client.post(
            "/push/users/user-1/settings",
            json={"data": {"x": 1}, "baseHash": None},
        )
        # Second push with wrong baseHash → 409
        conflict_resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"x": 2}, "baseHash": "wrong-hash"},
        )

    assert conflict_resp.status_code == 409
    assert len(recorded) == 2  # both pushes recorded
    conflict_entry = recorded[1]
    assert conflict_entry.action == "push"
    assert conflict_entry.success is False
    assert conflict_entry.status_code == 409


# ─── no audit_logger → no error ────────────────────────────────────────

@pytest.mark.asyncio
async def test_push_without_audit_logger_does_not_crash():
    """ When audit_logger is None (default), push must still work normally."""
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="settings",
                storagePath="users/{identity}/settings",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["self"])

    # No audit_logger passed → must default to None
    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"y": 2}, "baseHash": None},
        )
    assert resp.status_code == 200


# ─── auth denial (403) emits an audit entry with failure ────────────────

@pytest.mark.asyncio
async def test_denied_push_records_audit_entry():
    """A 403 auth denial must call audit_logger.record with success=False.

    Without this, only requests that pass the auth gate are ever audited — so
    denied (401/403) attempts leave no trace in the trail.
    """
    recorded: list[AuditEntry] = []

    class CapturingLogger(AuditLogger):
        async def record(self, entry: AuditEntry) -> None:
            recorded.append(entry)

    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="settings",
                storagePath="users/{identity}/settings",
                readRoles=["admin"],
                writeRoles=["admin"],  # a role the caller never holds
                encryption="none",
                maxBodyBytes=65536,
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=[])  # no roles → write denied

    router = create_sync_router(
        SyncRouterOptions(
            store=store, config=config, role_resolver=role_resolver, audit_logger=CapturingLogger()
        ),
    )
    app = FastAPI()
    app.include_router(router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"x": 1}, "baseHash": None},
        )

    assert resp.status_code == 403
    assert len(recorded) == 1
    assert recorded[0].action == "push"
    assert recorded[0].success is False
    assert recorded[0].status_code == 403
    assert recorded[0].collection == "settings"


@pytest.mark.asyncio
async def test_awaits_async_audit_logger_before_returning_push_response():
    # Cross-language divergence. Python does `await audit_logger.record(...)`, so an
    # async logger's write completes before the response is returned (this test).
    # TS calls `opts.auditLogger.record(...)` WITHOUT await, so an async logger is
    # fire-and-forget — the entry may not be written before the response, and a
    # rejected logger becomes an unhandled rejection. This is the reference for the
    # convergent durable behaviour; the TS side is pinned as it.fails in
    # router-emission.test.ts.
    audit_completed = False

    class SlowLogger(AuditLogger):
        async def record(self, entry: AuditEntry) -> None:
            nonlocal audit_completed
            await asyncio.sleep(0)
            audit_completed = True

    app, _ = _make_app_with_audit(SlowLogger())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"x": 1}, "baseHash": None},
        )

    assert resp.status_code == 200
    assert audit_completed is True  # Python awaits the record call before responding
