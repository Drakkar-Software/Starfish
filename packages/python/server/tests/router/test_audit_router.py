"""AuditLogger must be called on push operations in the Python router.
This test suite verifies that
SyncRouterOptions.audit_logger is wired through the push handler.
"""

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.router.route_builder import create_sync_router, SyncRouterOptions, AuthResult
from starfish_server.audit import AuditLogger, AuditEntry
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
    # fix not yet present → recorded is empty → FAILS
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
    # fix not yet present → recorded may be empty or missing the 409 entry → FAILS
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
