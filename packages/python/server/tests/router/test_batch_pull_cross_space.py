"""Cross-space batch pull tests.

Tests that /batch/pull authorises each requested collection entry
independently via the per-entry role enricher (simulating the spaces
_access registry) rather than requiring a per-space cap per request.

Key invariants tested:
 - member reads own space, gets Forbidden for sibling (per-entry auth)
 - owner reads all owned spaces (correct multi-space fan-out)
 - stranger gets Forbidden for every space
 - per-space-scoped cap (scope: "spaces/space-A/**") still blocks siblings
 - absent _access doc → Forbidden, not 200-empty
 - empty param-set array → empty result (no reads, no auth round-trips)
"""

import json
import urllib.parse

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from starfish_server.storage.memory import MemoryObjectStore


# ── fixtures ──────────────────────────────────────────────────────────────────

_SPACE_A_DOC = json.dumps({
    "data": {"owner": "alice", "members": ["alice", "bob"], "name": "Alpha"},
    "hash": "hash-A",
    "ts": 1000,
})

_SPACE_B_DOC = json.dumps({
    "data": {"owner": "alice", "members": ["alice"], "name": "Beta"},
    "hash": "hash-B",
    "ts": 2000,
})

_SPACE_C_DOC = json.dumps({
    "data": {"owner": "carol", "members": ["carol"], "name": "Gamma"},
    "hash": "hash-C",
    "ts": 3000,
})

_SEED_DATA: dict[str, str] = {
    "spaces/space-A/_access": _SPACE_A_DOC,
    "spaces/space-B/_access": _SPACE_B_DOC,
    "spaces/space-C/_access": _SPACE_C_DOC,
}

_SPACEACCESS_COLLECTION = CollectionConfig(
    name="spaceaccess",
    storagePath="spaces/{spaceId}/_access",
    readRoles=["space:member"],
    writeRoles=["space:owner"],
    encryption="none",
    maxBodyBytes=65536,
)


# ── helper ────────────────────────────────────────────────────────────────────

def make_app(
    caller_identity: str,
    caller_roles: list[str],
    scope_paths: list[str] | None = None,
) -> FastAPI:
    """Build a seeded FastAPI app with the spaceaccess collection and enricher."""
    store = MemoryObjectStore(data=dict(_SEED_DATA))

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(
            identity=caller_identity,
            roles=caller_roles,
            scope_paths=scope_paths,
        )

    async def enricher(auth: AuthResult, params: dict[str, str]) -> list[str]:
        space_id = params.get("spaceId")
        if not space_id:
            return []
        raw = await store.get_string(f"spaces/{space_id}/_access")
        if not raw:
            return []  # allowTofu:false — absent doc → no roles
        try:
            doc = json.loads(raw)
        except Exception:
            return []
        d = doc.get("data", {})
        owner: str | None = d.get("owner")
        members: list[str] = d.get("members", []) if isinstance(d.get("members"), list) else []
        roles: list[str] = []
        if auth.identity == owner:
            roles.append("space:owner")
        if auth.identity == owner or auth.identity in members:
            roles.append("space:member")
        return roles

    config = SyncConfig(
        version=1,
        collections=[_SPACEACCESS_COLLECTION],
    )
    router = create_sync_router(
        SyncRouterOptions(
            store=store,
            config=config,
            role_resolver=role_resolver,
            role_enricher=enricher,
        )
    )
    app = FastAPI()
    app.include_router(router)
    return app


def _params_qs(obj: dict) -> str:
    """URL-encode a params dict into ?params=<json> query string value."""
    return urllib.parse.urlencode({"params": json.dumps(obj)})


# ── tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_member_reads_own_space_forbidden_for_sibling():
    """bob is in space-A but not space-B; expects data for space-A, Forbidden for space-B."""
    app = make_app("bob", [])
    url = f"/batch/pull?collections=spaceaccess&{_params_qs({'spaceaccess': [{'spaceId': 'space-A'}, {'spaceId': 'space-B'}]})}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(url)
    assert resp.status_code == 200
    entries = resp.json()["collections"]["spaceaccess"]
    # space-A: bob is a member → ok
    assert "error" not in entries[0]
    assert entries[0]["data"]["name"] == "Alpha"
    # space-B: bob is NOT a member → Forbidden
    assert entries[1]["error"] == "Forbidden"
    assert "data" not in entries[1]


@pytest.mark.asyncio
async def test_owner_reads_all_owned_spaces():
    """alice owns space-A and space-B; both entries succeed."""
    app = make_app("alice", [])
    url = f"/batch/pull?collections=spaceaccess&{_params_qs({'spaceaccess': [{'spaceId': 'space-A'}, {'spaceId': 'space-B'}]})}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(url)
    assert resp.status_code == 200
    entries = resp.json()["collections"]["spaceaccess"]
    assert "error" not in entries[0]
    assert entries[0]["data"]["owner"] == "alice"
    assert "error" not in entries[1]
    assert entries[1]["data"]["owner"] == "alice"


@pytest.mark.asyncio
async def test_stranger_forbidden_every_space():
    """dave has no membership in any space; every entry returns Forbidden."""
    app = make_app("dave", [])
    url = f"/batch/pull?collections=spaceaccess&{_params_qs({'spaceaccess': [{'spaceId': 'space-A'}, {'spaceId': 'space-B'}, {'spaceId': 'space-C'}]})}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(url)
    assert resp.status_code == 200
    for entry in resp.json()["collections"]["spaceaccess"]:
        assert entry["error"] == "Forbidden"


@pytest.mark.asyncio
async def test_per_space_cap_blocks_siblings():
    """alice with scope_paths=["spaces/space-A/**"]: space-A ok, space-B Forbidden (scope regression)."""
    app = make_app("alice", [], scope_paths=["spaces/space-A/**"])
    url = f"/batch/pull?collections=spaceaccess&{_params_qs({'spaceaccess': [{'spaceId': 'space-A'}, {'spaceId': 'space-B'}]})}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(url)
    assert resp.status_code == 200
    entries = resp.json()["collections"]["spaceaccess"]
    assert "error" not in entries[0]  # space-A within scope
    assert entries[1]["error"] == "Forbidden"  # space-B outside scope


@pytest.mark.asyncio
async def test_strict_tofu_absent_space_is_forbidden():
    """space-MISSING has no fixture; enricher returns [] → Forbidden (not 200-empty)."""
    app = make_app("alice", [])
    url = f"/batch/pull?collections=spaceaccess&{_params_qs({'spaceaccess': [{'spaceId': 'space-MISSING'}]})}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(url)
    assert resp.status_code == 200
    entry = resp.json()["collections"]["spaceaccess"][0]
    assert entry["error"] == "Forbidden"
    # Must NOT be an empty 200 data object (that would be the TOFU-open path).
    assert "data" not in entry


@pytest.mark.asyncio
async def test_mixed_own_absent_unjoined():
    """alice: space-A ok, space-MISSING Forbidden (no TOFU), space-C Forbidden (not a member)."""
    app = make_app("alice", [])
    url = f"/batch/pull?collections=spaceaccess&{_params_qs({'spaceaccess': [{'spaceId': 'space-A'}, {'spaceId': 'space-MISSING'}, {'spaceId': 'space-C'}]})}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(url)
    assert resp.status_code == 200
    entries = resp.json()["collections"]["spaceaccess"]
    assert "error" not in entries[0]
    assert entries[0]["data"]["owner"] == "alice"
    assert entries[1]["error"] == "Forbidden"
    assert entries[2]["error"] == "Forbidden"


@pytest.mark.asyncio
async def test_empty_param_set_returns_empty_result():
    """An empty param-set array means zero reads → an empty result array."""
    app = make_app("alice", [])
    url = f"/batch/pull?collections=spaceaccess&{_params_qs({'spaceaccess': []})}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(url)
    assert resp.status_code == 200
    assert resp.json()["collections"]["spaceaccess"] == []


@pytest.mark.asyncio
async def test_collection_not_found_per_entry_errors():
    """An unknown collection with N param-sets returns N per-entry 'Collection not found' errors."""
    app = make_app("alice", [])
    url = f"/batch/pull?collections=nonexistent&{_params_qs({'nonexistent': [{'spaceId': 'space-A'}, {'spaceId': 'space-B'}]})}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(url)
    assert resp.status_code == 200
    entries = resp.json()["collections"]["nonexistent"]
    assert len(entries) == 2
    for entry in entries:
        assert entry["error"] == "Collection not found"


@pytest.mark.asyncio
async def test_path_traversal_rejected():
    """spaceId='../../../etc/passwd' is rejected with 'Invalid path parameter' or 'Forbidden'."""
    app = make_app("alice", [])
    url = f"/batch/pull?collections=spaceaccess&{_params_qs({'spaceaccess': [{'spaceId': '../../../etc/passwd'}]})}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(url)
    assert resp.status_code == 200
    entry = resp.json()["collections"]["spaceaccess"][0]
    assert entry["error"] in ("Invalid path parameter", "Forbidden")


@pytest.mark.asyncio
async def test_result_index_aligned_to_input_params():
    """4 entries: alice-readable, missing, alice-readable, non-member — result is index-aligned."""
    app = make_app("alice", [])
    url = f"/batch/pull?collections=spaceaccess&{_params_qs({'spaceaccess': [{'spaceId': 'space-A'}, {'spaceId': 'space-MISSING'}, {'spaceId': 'space-B'}, {'spaceId': 'space-C'}]})}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(url)
    assert resp.status_code == 200
    entries = resp.json()["collections"]["spaceaccess"]
    assert len(entries) == 4
    assert entries[0]["data"]["name"] == "Alpha"   # space-A: alice is owner → ok
    assert entries[1]["error"] == "Forbidden"       # space-MISSING: absent → no TOFU
    assert entries[2]["data"]["name"] == "Beta"    # space-B: alice is owner → ok
    assert entries[3]["error"] == "Forbidden"       # space-C: carol's space → Forbidden
