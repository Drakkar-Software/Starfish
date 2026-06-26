"""Tests for FastAPI sync router — ported from router.test.ts."""

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import (
    SyncConfig,
    CollectionConfig,
    FieldPermission,
    RateLimitConfig,
)
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from tests.helpers import MemoryObjectStore


def _build_app(
    identity: str = "user-1",
    roles: list[str] | None = None,
    rate_limit: RateLimitConfig | None = None,
) -> tuple[FastAPI, MemoryObjectStore]:
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
            CollectionConfig(
                name="public-config",
                storagePath="app/config",
                readRoles=["public"],
                writeRoles=["admin"],
                encryption="none",
                maxBodyBytes=65536,
            ),
        ],
        rateLimit=rate_limit,
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=roles or [])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


@pytest.mark.asyncio
async def test_pull_empty_collection():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/users/user-1/settings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"] == {}
    assert body["hash"] == ""


@pytest.mark.asyncio
async def test_push_then_pull_roundtrip():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        push_resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"theme": "dark"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        assert push_resp.status_code == 200
        push_body = push_resp.json()
        assert len(push_body["hash"]) == 64

        pull_resp = await client.get("/pull/users/user-1/settings")
        assert pull_resp.status_code == 200
        pull_body = pull_resp.json()
        assert pull_body["data"] == {"theme": "dark"}
        assert pull_body["hash"] == push_body["hash"]


@pytest.mark.asyncio
async def test_self_role_denies_other_user():
    app, _ = _build_app(identity="user-1")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/users/user-2/settings")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_public_collection_readable():
    app, _ = _build_app(identity="admin-user", roles=["admin"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Push as admin
        await client.post(
            "/push/app/config",
            json={"data": {"version": "2.0"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        # Pull publicly
        resp = await client.get("/pull/app/config")
    assert resp.status_code == 200
    assert resp.json()["data"] == {"version": "2.0"}


@pytest.mark.asyncio
async def test_non_admin_cannot_push_admin_collection():
    app, _ = _build_app(identity="regular-user", roles=[])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/app/config",
            json={"data": {"maintenance": True}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_body_limit_enforced():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"x": "a"}, "baseHash": None},
            headers={
                "content-type": "application/json",
                "content-length": "999999",
            },
        )
    assert resp.status_code == 413


@pytest.mark.asyncio
async def test_deeply_nested_body_rejected_not_crash():
    """A deeply-nested JSON body is rejected 400, not an unhandled RecursionError/500.

    The body is small (~30 KB) so it passes the size guard, but its nesting depth far
    exceeds MAX_DOC_DEPTH; the push handler parses defensively and runs the iterative
    depth check before the recursive `deep_sanitize`.
    """
    app, _ = _build_app()
    depth = 5000  # well past CPython's recursion limit and MAX_DOC_DEPTH (64)
    raw = '{"data":' + '{"a":' * depth + "1" + "}" * depth + ',"baseHash":null}'
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/settings",
            content=raw,
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_batch_pull_resolves_identity_from_authenticated_caller():
    """A `{identity}`-templated collection resolves to the caller's OWN document.

    Batch pull auto-fills `{identity}` from the authenticated caller and folds in the
    resulting `self` role, so a per-user collection is reachable through the batch
    endpoint (it used to be rejected as "not batch-pullable"). A singleton collection
    in the same request is still served normally.
    """
    import json as _json

    app, store = _build_app(roles=[])
    await store.put(
        "users/user-1/settings",
        _json.dumps({"data": {"theme": "dark"}, "hash": "h", "ts": 0}),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull?collections=settings,public-config")
    assert resp.status_code == 200
    cols = resp.json()["collections"]
    assert "error" not in cols["settings"][0]
    assert cols["settings"][0]["data"] == {"theme": "dark"}  # the caller's own doc
    assert "data" in cols["public-config"][0]  # singleton, public-read


def test_json_depth_within_helper():
    """The depth check is iterative and bounds dict + list nesting."""
    from starfish_server.router.helpers import json_depth_within, MAX_DOC_DEPTH

    assert json_depth_within({"a": {"b": {"c": 1}}}, limit=3) is True
    assert json_depth_within({"a": {"b": {"c": 1}}}, limit=2) is False
    assert json_depth_within([[[1]]], limit=3) is True
    assert json_depth_within([[[1]]], limit=2) is False
    # A structure deeper than the default ceiling is rejected without recursing.
    deep: dict = {}
    cur = deep
    for _ in range(MAX_DOC_DEPTH + 10):
        cur["a"] = {}
        cur = cur["a"]
    assert json_depth_within(deep) is False


def test_json_depth_within_exact_default_boundary():
    """Nesting to exactly MAX_DOC_DEPTH passes; one level deeper is rejected.

    The existing helper test probes small explicit limits and a far-past-ceiling
    structure; this pins the off-by-one at the *default* ceiling for both pure-dict
    and alternating dict/list nesting (so both branches of the walker are exercised).
    """
    from starfish_server.router.helpers import json_depth_within, MAX_DOC_DEPTH

    def nested_dict(levels: int) -> dict:
        root: dict = {}
        cur = root
        for _ in range(levels - 1):
            cur["a"] = {}
            cur = cur["a"]
        cur["a"] = 1  # innermost scalar — does not add a container level
        return root

    def nested_mixed(levels: int):
        node: object = 1
        for i in range(levels):
            node = {"a": node} if i % 2 == 0 else [node]
        return node

    assert json_depth_within(nested_dict(MAX_DOC_DEPTH)) is True
    assert json_depth_within(nested_dict(MAX_DOC_DEPTH + 1)) is False
    assert json_depth_within(nested_mixed(MAX_DOC_DEPTH)) is True
    assert json_depth_within(nested_mixed(MAX_DOC_DEPTH + 1)) is False


@pytest.mark.parametrize(
    "ident",
    [
        "‮",            # RIGHT-TO-LEFT OVERRIDE (display-spoofing / Trojan-source)
        "аdmin",        # Cyrillic 'а' homograph of ASCII 'a' (looks like "admin")
        "café",         # non-ASCII letter (é)
        "user․settings",  # ONE DOT LEADER (looks like a '.')
    ],
    ids=["rtl-override", "cyrillic-homograph", "non-ascii-letter", "dot-leader"],
    # NB: ASCII control chars (NUL, \r, \n) are rejected even earlier — the HTTP
    # client/transport refuses to put them in a URL — so the server's regex is the
    # second of two layers; this case probes printable spoofing chars that DO arrive.
)
@pytest.mark.asyncio
async def test_unicode_and_control_char_path_params_are_rejected(ident: str):
    """Path params are constrained to an ASCII charset, so homograph / RTL-override /
    control-char identities are rejected 400 BEFORE auth or any store read.

    ``validate_path_segment`` (`^[a-zA-Z0-9._:@-]+$`) runs first in every handler, so a
    spoofing identity can never reach the cap resolver or be persisted as a storage key —
    closing the homograph-confusion door that a bytes-only `..`/`//` guard would leave open.
    """
    app, _ = _build_app(roles=["self"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(f"/pull/users/{ident}/settings")
    assert resp.status_code == 400
    assert resp.json()["error"] == "Invalid path parameter"


@pytest.mark.asyncio
async def test_batch_pull_ignores_empty_csv_slots():
    """Empty slots in the `collections` CSV (leading/trailing/double commas) are
    dropped, not turned into an empty-name lookup that reports "Collection not found".
    """
    app, _ = _build_app(roles=["public"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull?collections=,public-config,,")
    assert resp.status_code == 200
    cols = resp.json()["collections"]
    assert list(cols.keys()) == ["public-config"]  # empties never become keys
    assert "data" in cols["public-config"][0]


@pytest.mark.asyncio
async def test_batch_pull_honors_ttl_expiry():
    """Batch pull applies the same TTL expiry as the standalone pull (TS already has this).

    A document older than the collection's `ttlMs` is served as empty `{}` data through
    the batch endpoint too — otherwise an expired ephemeral doc would leak via the
    multi-document path even though the standalone pull zeroes it.
    """
    import json as _json

    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="ephemeral",
                storagePath="ephemeral/data",
                readRoles=["public"],
                writeRoles=["admin"],
                encryption="none",
                maxBodyBytes=65536,
                ttlMs=1000,
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="u", roles=["public"])

    router = create_sync_router(SyncRouterOptions(store=store, config=config, role_resolver=role_resolver))
    app = FastAPI()
    app.include_router(router)

    # Seed an already-expired doc (doc-level write-time far in the past).
    await store.put(
        "ephemeral/data",
        _json.dumps({"v": 1, "data": {"x": 1}, "hash": "h", "ts": 1}),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull?collections=ephemeral")
    assert resp.status_code == 200
    assert resp.json()["collections"]["ephemeral"][0]["data"] == {}  # expired → zeroed


@pytest.mark.asyncio
async def test_batch_pull_all_empty_csv_returns_empty_result_set():
    """A present-but-all-empty CSV (`,,`) resolves to no names → 200 with `{}`.

    The 400 guard fires only when the `collections` param is absent/empty, not when it
    contains only empty slots — so `,,` is a no-op query, not an error. (TS parity.)
    """
    app, _ = _build_app(roles=["public"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull?collections=,,")
    assert resp.status_code == 200
    assert resp.json()["collections"] == {}


def _build_param_app(
    identity: str = "user-1",
    roles: list[str] | None = None,
) -> tuple[FastAPI, MemoryObjectStore]:
    """App with a `self`-gated per-user collection and a `{teamId}` collection that
    takes a caller-supplied param. Mirrors the TS `makeParamRouter` harness."""
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="public-data", storagePath="public/data",
                readRoles=["public"], writeRoles=["admin"],
                encryption="none", maxBodyBytes=65536,
            ),
            CollectionConfig(
                name="journal", storagePath="users/{identity}/journal",
                readRoles=["self"], writeRoles=["self"],
                encryption="none", maxBodyBytes=65536,
            ),
            CollectionConfig(
                name="team-notes", storagePath="teams/{teamId}/notes",
                readRoles=["public"], writeRoles=["admin"],
                encryption="none", maxBodyBytes=65536,
            ),
            CollectionConfig(
                name="team-journal", storagePath="users/{identity}/teams/{teamId}/notes",
                readRoles=["public"], writeRoles=["self"],
                encryption="none", maxBodyBytes=65536,
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=roles or [])

    router = create_sync_router(SyncRouterOptions(store=store, config=config, role_resolver=role_resolver))
    app = FastAPI()
    app.include_router(router)
    return app, store


@pytest.mark.asyncio
async def test_batch_pull_resolves_supplied_non_identity_param():
    """A caller-supplied `{teamId}` is substituted into the storage key."""
    import json as _json

    app, store = _build_param_app()
    await store.put(
        "teams/42/notes",
        _json.dumps({"data": {"topic": "launch"}, "hash": "h", "ts": 0}),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/batch/pull",
            params={"collections": "team-notes", "params": _json.dumps({"team-notes": [{"teamId": "42"}]})},
        )
    assert resp.status_code == 200
    assert resp.json()["collections"]["team-notes"][0]["data"] == {"topic": "launch"}


@pytest.mark.asyncio
async def test_batch_pull_auto_fills_identity_for_self_gated_collection():
    """No params supplied — `{identity}` is filled from the caller and the resulting
    `self` role satisfies the collection's readRoles, so the caller reads their OWN doc."""
    import json as _json

    app, store = _build_param_app()
    await store.put(
        "users/user-1/journal",
        _json.dumps({"data": {"entries": 3}, "hash": "h", "ts": 0}),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull?collections=journal")
    assert resp.status_code == 200
    assert resp.json()["collections"]["journal"][0]["data"] == {"entries": 3}


@pytest.mark.asyncio
async def test_batch_pull_denies_forged_identity_on_self_gated_collection():
    """A supplied identity != the caller earns no `self` role → Forbidden, no data leak."""
    import json as _json

    app, store = _build_param_app(identity="user-1")
    await store.put(
        "users/user-2/journal",
        _json.dumps({"data": {"secret": True}, "hash": "h", "ts": 0}),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/batch/pull",
            params={"collections": "journal", "params": _json.dumps({"journal": [{"identity": "user-2"}]})},
        )
    assert resp.status_code == 200
    cols = resp.json()["collections"]
    assert cols["journal"][0]["error"] == "Forbidden"
    assert "data" not in cols["journal"][0]


@pytest.mark.asyncio
async def test_batch_pull_reports_missing_required_param():
    """A required `{teamId}` with no supplied value (and not identity-auto-fillable)
    yields a per-collection error, not data."""
    app, _ = _build_param_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull?collections=team-notes")
    assert resp.status_code == 200
    cols = resp.json()["collections"]
    assert cols["team-notes"][0]["error"] == "Missing required path parameter"
    assert "data" not in cols["team-notes"][0]


@pytest.mark.asyncio
async def test_batch_pull_merges_auto_identity_with_supplied_param():
    """team-journal needs BOTH {identity} (auto-filled) and {teamId} (supplied).
    Getting data back proves the two sources merge into the resolved key — a
    regression that gated auto-fill on "no params at all" would miss identity here
    and return "Missing required path parameter" instead."""
    import json as _json

    app, store = _build_param_app()
    await store.put(
        "users/user-1/teams/42/notes",
        _json.dumps({"data": {"n": 7}, "hash": "h", "ts": 0}),
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/batch/pull",
            params={"collections": "team-journal", "params": _json.dumps({"team-journal": [{"teamId": "42"}]})},
        )
    assert resp.status_code == 200
    cols = resp.json()["collections"]
    assert "error" not in cols["team-journal"][0]
    assert cols["team-journal"][0]["data"] == {"n": 7}


@pytest.mark.asyncio
async def test_batch_pull_rejects_malformed_params_blob():
    """A `params` value that is not JSON is a client framing error → whole-request 400."""
    app, _ = _build_param_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull", params={"collections": "public-data", "params": "not-json"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "Invalid params parameter"


@pytest.mark.asyncio
async def test_batch_pull_rejects_unsafe_param_value_per_collection():
    """A param value with `/` fails the per-segment charset check for that collection
    only; a sibling singleton in the same request is still served."""
    import json as _json

    app, _ = _build_param_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/batch/pull",
            params={
                "collections": "team-notes,public-data",
                "params": _json.dumps({"team-notes": [{"teamId": "a/b"}]}),
            },
        )
    assert resp.status_code == 200
    cols = resp.json()["collections"]
    assert cols["team-notes"][0]["error"] == "Invalid path parameter"
    assert "data" in cols["public-data"][0]


@pytest.mark.asyncio
async def test_batch_pull_blocks_dotdot_traversal_via_key_guard():
    """`..` passes the per-segment charset (dots allowed) but composes a traversal key,
    which is_unsafe_document_key rejects before any store read."""
    import json as _json

    app, _ = _build_param_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/batch/pull",
            params={"collections": "team-notes", "params": _json.dumps({"team-notes": [{"teamId": ".."}]})},
        )
    assert resp.status_code == 200
    assert resp.json()["collections"]["team-notes"][0]["error"] == "Invalid path parameter"


@pytest.mark.asyncio
async def test_batch_pull_applies_ttl_against_resolved_key():
    """Guards the param case of the TTL read: the stored-doc timestamp is read
    from the RESOLVED `users/user-1/ephemeral` key, not the `{identity}` template.
    An expired doc is zeroed exactly as on the standalone path."""
    import json as _json

    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="user-ephemeral", storagePath="users/{identity}/ephemeral",
                readRoles=["self"], writeRoles=["self"],
                encryption="none", maxBodyBytes=65536, ttlMs=1000,
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=[])

    router = create_sync_router(SyncRouterOptions(store=store, config=config, role_resolver=role_resolver))
    app = FastAPI()
    app.include_router(router)

    await store.put(
        "users/user-1/ephemeral",
        _json.dumps({"data": {"v": 1}, "hash": "h", "ts": 1}),  # write-time far in the past
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull?collections=user-ephemeral")
    assert resp.status_code == 200
    assert resp.json()["collections"]["user-ephemeral"][0]["data"] == {}  # expired → zeroed


@pytest.mark.asyncio
async def test_batch_pull_enforces_cap_scope_paths_against_resolved_key():
    """A cap-cert resolver returns `scope_paths`; the batch handler re-checks each
    RESOLVED key against it (the resolver can't path-bind /batch/pull). A caller
    scoped to team 42 reads 42 but is Forbidden on 99 — batch can't side-step the
    per-path scope."""
    import json as _json

    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="team-notes", storagePath="teams/{teamId}/notes",
                readRoles=["public"], writeRoles=["admin"],
                encryption="none", maxBodyBytes=65536,
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=[], scope_paths=["teams/42/notes"])

    router = create_sync_router(SyncRouterOptions(store=store, config=config, role_resolver=role_resolver))
    app = FastAPI()
    app.include_router(router)

    await store.put("teams/42/notes", _json.dumps({"data": {"ok": 1}, "hash": "h", "ts": 0}))
    await store.put("teams/99/notes", _json.dumps({"data": {"secret": 1}, "hash": "h", "ts": 0}))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # One fan-out request so the per-ENTRY scope check is exercised (not just
        # the per-collection one): 42 is in scope, 99 is not.
        resp = await client.get(
            "/batch/pull",
            params={"collections": "team-notes", "params": _json.dumps({"team-notes": [{"teamId": "42"}, {"teamId": "99"}]})},
        )
    notes = resp.json()["collections"]["team-notes"]
    assert notes[0]["data"] == {"ok": 1}
    assert notes[1]["error"] == "Forbidden"
    assert "data" not in notes[1]


@pytest.mark.asyncio
async def test_batch_pull_rejects_too_many_collections():
    """A batch naming more than `max_collections_per_batch` is rejected up front —
    bounds the per-request work one signed request can drive."""
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(name=n, storagePath=n, readRoles=["public"],
                             writeRoles=["admin"], encryption="none", maxBodyBytes=65536)
            for n in ("a", "b", "c")
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="u", roles=[])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver, max_collections_per_batch=2)
    )
    app = FastAPI()
    app.include_router(router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull?collections=a,b,c")
    assert resp.status_code == 400
    assert resp.json()["error"] == "Too many collections"


@pytest.mark.asyncio
async def test_batch_pull_writes_audit_records_for_denials_and_successes():
    """Batch pull records an audit entry per collection on auth denials and
    successful reads — mirroring the standalone pull's audit points."""
    import json as _json
    from starfish_protocol.audit import AuditLogger, AuditEntry

    class _CollectingAudit(AuditLogger):
        def __init__(self) -> None:
            self.records: list[AuditEntry] = []

        async def record(self, entry: AuditEntry) -> None:
            self.records.append(entry)

    audit = _CollectingAudit()
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(name="team-notes", storagePath="teams/{teamId}/notes",
                             readRoles=["public"], writeRoles=["admin"], encryption="none", maxBodyBytes=65536),
            CollectionConfig(name="journal", storagePath="users/{identity}/journal",
                             readRoles=["self"], writeRoles=["self"], encryption="none", maxBodyBytes=65536),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=[])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver, audit_logger=audit)
    )
    app = FastAPI()
    app.include_router(router)
    await store.put("teams/42/notes", _json.dumps({"data": {"ok": 1}, "hash": "h", "ts": 0}))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # team-notes (public, in scope) → success; journal forged identity → Forbidden.
        await client.get(
            "/batch/pull",
            params={
                "collections": "team-notes,journal",
                "params": _json.dumps({"team-notes": [{"teamId": "42"}], "journal": [{"identity": "user-2"}]}),
            },
        )
    pulls = [r for r in audit.records if r.action == "pull"]
    tn = next(r for r in pulls if r.collection == "team-notes")
    jr = next(r for r in pulls if r.collection == "journal")
    assert tn.success is True and tn.status_code == 200
    assert jr.success is False and jr.status_code == 403


@pytest.mark.asyncio
async def test_batch_pull_audits_degrade_when_cap_invalid():
    """An invalid/revoked cap degrades to anonymous (public collections still
    served) AND records a request-level audit entry, so the auth failure isn't an
    audit blind spot."""
    from starfish_protocol.audit import AuditLogger, AuditEntry

    class _CollectingAudit(AuditLogger):
        def __init__(self) -> None:
            self.records: list[AuditEntry] = []

        async def record(self, entry: AuditEntry) -> None:
            self.records.append(entry)

    class _Revoked(Exception):
        status = 403

    audit = _CollectingAudit()
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(name="public-config", storagePath="app/config",
                             readRoles=["public"], writeRoles=["admin"], encryption="none", maxBodyBytes=65536),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        raise _Revoked("revoked")

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver, audit_logger=audit)
    )
    app = FastAPI()
    app.include_router(router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull?collections=public-config")
    assert resp.status_code == 200
    assert "data" in resp.json()["collections"]["public-config"][0]  # public served despite bad cap
    pulls = [r for r in audit.records if r.action == "pull"]
    degrade = next(r for r in pulls if r.collection == "")
    assert degrade.success is False and degrade.status_code == 403
    ok = next(r for r in pulls if r.collection == "public-config")
    assert ok.success is True and ok.status_code == 200


@pytest.mark.asyncio
async def test_batch_pull_audit_failure_does_not_corrupt_result():
    """A throwing audit logger must not relabel a successful read as an error —
    the success record runs inside the per-collection read try/except, so audit is
    best-effort and swallowed."""
    import json as _json
    from starfish_protocol.audit import AuditLogger, AuditEntry

    class _ThrowingAudit(AuditLogger):
        async def record(self, entry: AuditEntry) -> None:
            raise RuntimeError("audit down")

    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(name="team-notes", storagePath="teams/{teamId}/notes",
                             readRoles=["public"], writeRoles=["admin"], encryption="none", maxBodyBytes=65536),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="u", roles=[])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver, audit_logger=_ThrowingAudit())
    )
    app = FastAPI()
    app.include_router(router)
    await store.put("teams/42/notes", _json.dumps({"data": {"ok": 1}, "hash": "h", "ts": 0}))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/batch/pull",
            params={"collections": "team-notes", "params": _json.dumps({"team-notes": [{"teamId": "42"}]})},
        )
    assert resp.status_code == 200
    col = resp.json()["collections"]["team-notes"][0]
    assert col["data"] == {"ok": 1}
    assert "error" not in col


@pytest.mark.asyncio
async def test_batch_pull_ignores_params_outside_template():
    """Caller-supplied keys outside a collection's template are dropped (parity
    with the standalone path) — not validated or passed downstream. Even an unsafe
    value for a non-template key is ignored, so the collection still resolves."""
    import json as _json

    app, store = _build_param_app()
    await store.put("teams/42/notes", _json.dumps({"data": {"ok": 1}, "hash": "h", "ts": 0}))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/batch/pull",
            params={
                "collections": "team-notes",
                "params": _json.dumps({"team-notes": [{"teamId": "42", "junk": "a/b"}]}),
            },
        )
    assert resp.status_code == 200
    col = resp.json()["collections"]["team-notes"][0]
    assert "error" not in col
    assert col["data"] == {"ok": 1}


@pytest.mark.asyncio
async def test_batch_pull_fans_in_many_docs_of_one_collection():
    """The core of the generalization: one collection name, an array of param-sets,
    one result array aligned to input order."""
    import json as _json

    app, store = _build_param_app()
    await store.put("teams/42/notes", _json.dumps({"data": {"topic": "a"}, "hash": "h", "ts": 0}))
    await store.put("teams/99/notes", _json.dumps({"data": {"topic": "b"}, "hash": "h", "ts": 0}))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/batch/pull",
            params={"collections": "team-notes", "params": _json.dumps({"team-notes": [{"teamId": "42"}, {"teamId": "99"}]})},
        )
    assert resp.status_code == 200
    notes = resp.json()["collections"]["team-notes"]
    assert [e["data"] for e in notes] == [{"topic": "a"}, {"topic": "b"}]


@pytest.mark.asyncio
async def test_batch_pull_returns_mixed_per_document_results():
    """Entries stay index-aligned: a valid set yields data, a set missing a required
    param yields an error in the SAME position."""
    import json as _json

    app, store = _build_param_app()
    await store.put("teams/42/notes", _json.dumps({"data": {"topic": "a"}, "hash": "h", "ts": 0}))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/batch/pull",
            params={"collections": "team-notes", "params": _json.dumps({"team-notes": [{"teamId": "42"}, {}]})},
        )
    notes = resp.json()["collections"]["team-notes"]
    assert notes[0]["data"] == {"topic": "a"}
    assert notes[1]["error"] == "Missing required path parameter"


@pytest.mark.asyncio
async def test_batch_pull_not_found_emits_one_entry_per_set():
    """An unknown collection with N param-sets returns N error entries so the result
    array length matches the caller's input (batch_pull_many indexes by position)."""
    import json as _json

    app, _ = _build_param_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/batch/pull",
            params={"collections": "nope", "params": _json.dumps({"nope": [{}, {}, {}]})},
        )
    assert resp.status_code == 200
    nope = resp.json()["collections"]["nope"]
    assert len(nope) == 3
    assert all(e["error"] == "Collection not found" for e in nope)


@pytest.mark.asyncio
async def test_batch_pull_empty_param_list_returns_empty_array():
    """An empty param-set list means zero reads → an empty result array."""
    import json as _json

    app, _ = _build_param_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/batch/pull",
            params={"collections": "team-notes", "params": _json.dumps({"team-notes": []})},
        )
    assert resp.status_code == 200
    assert resp.json()["collections"]["team-notes"] == []


@pytest.mark.asyncio
async def test_batch_pull_rejects_non_array_params_value():
    """The pre-generalization object shape is no longer accepted — a bare object per
    collection is a framing error → whole-request 400."""
    import json as _json

    app, _ = _build_param_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/batch/pull",
            params={"collections": "team-notes", "params": _json.dumps({"team-notes": {"teamId": "42"}})},
        )
    assert resp.status_code == 400
    assert resp.json()["error"] == "Invalid params parameter"


@pytest.mark.asyncio
async def test_batch_pull_rejects_fan_out_exceeding_total_reads():
    """The distinct-name cap is not sufficient: a single name with an oversized
    param-set array must also be rejected by the total-reads guard."""
    import json as _json

    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(name="team-notes", storagePath="teams/{teamId}/notes",
                             readRoles=["public"], writeRoles=["admin"], encryption="none", maxBodyBytes=65536),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="u", roles=[])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver, max_collections_per_batch=2)
    )
    app = FastAPI()
    app.include_router(router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/batch/pull",
            params={"collections": "team-notes", "params": _json.dumps({"team-notes": [{"teamId": "1"}, {"teamId": "2"}, {"teamId": "3"}]})},
        )
    assert resp.status_code == 400
    assert resp.json()["error"] == "Too many collections"


@pytest.mark.asyncio
async def test_conflict_on_stale_hash():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/push/users/user-1/settings",
            json={"data": {"v": 1}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        resp = await client.post(
            "/push/users/user-1/settings",
            json={"data": {"v": 2}, "baseHash": "wrong-hash"},
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 409
    assert resp.json()["error"] == "hash_mismatch"




def _build_delegated_app(
    identity: str = "user-1",
    roles: list[str] | None = None,
) -> tuple[FastAPI, MemoryObjectStore]:
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="vault",
                storagePath="users/{identity}/vault",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="delegated",
                maxBodyBytes=65536,
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=roles or [])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


@pytest.mark.asyncio
async def test_delegated_stores_data_as_is_no_server_encryption():
    """Server stores delegated data in plaintext — encryption is client's job."""
    app, store = _build_delegated_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        push_resp = await client.post(
            "/push/users/user-1/vault",
            json={"data": {"_encrypted": "client-encrypted-blob"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        assert push_resp.status_code == 200

        pull_resp = await client.get("/pull/users/user-1/vault")
        assert pull_resp.status_code == 200
        assert pull_resp.json()["data"] == {"_encrypted": "client-encrypted-blob"}

    # Raw storage contains the data as-is (no server-side encryption)
    import json
    raw = await store.get_string("users/user-1/vault")
    assert raw is not None
    doc = json.loads(raw)
    assert doc["data"]["_encrypted"] == "client-encrypted-blob"


@pytest.mark.asyncio
async def test_delegated_skips_incremental_sync():
    """Delegated mode implies clientEncrypted — checkpoint is ignored."""
    app, _ = _build_delegated_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/push/users/user-1/vault",
            json={"data": {"_encrypted": "blob1"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
        # With checkpoint, should still return full data (not filtered)
        resp = await client.get("/pull/users/user-1/vault?checkpoint=0")
        assert resp.status_code == 200
        assert resp.json()["data"] == {"_encrypted": "blob1"}


# ── bundle / batch per-collection authorization + field permissions ──────────


def _app_for(store: MemoryObjectStore, config: SyncConfig, identity: str, roles: list[str]) -> FastAPI:
    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=roles)

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver)
    )
    app = FastAPI()
    app.include_router(router)
    return app


async def _push(app: FastAPI, path: str, data: dict) -> int:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(path, json={"data": data, "baseHash": None}, headers={"content-type": "application/json"})
    return resp.status_code


@pytest.mark.asyncio
async def test_bundle_pull_omits_unauthorized_member():
    config = SyncConfig(version=1, collections=[
        CollectionConfig(name="prefs", storagePath="users/{identity}/data", readRoles=["self"], writeRoles=["self"], encryption="none", maxBodyBytes=65536, bundle="ud"),
        CollectionConfig(name="secret", storagePath="users/{identity}/data", readRoles=["admin"], writeRoles=["admin"], encryption="none", maxBodyBytes=65536, bundle="ud"),
    ])
    store = MemoryObjectStore()
    seed = _app_for(store, config, "user-1", ["self", "admin"])
    assert await _push(seed, "/push/users/user-1/data/prefs", {"color": "blue"}) == 200
    assert await _push(seed, "/push/users/user-1/data/secret", {"ssn": "123"}) == 200

    self_app = _app_for(store, config, "user-1", ["self"])
    async with AsyncClient(transport=ASGITransport(app=self_app), base_url="http://test") as client:
        resp = await client.get("/pull/users/user-1/data")
    assert resp.status_code == 200
    body = resp.json()
    assert body["collections"]["prefs"]["data"] == {"color": "blue"}
    assert "secret" not in body["collections"]  # caller lacks admin → omitted, not leaked


@pytest.mark.asyncio
async def test_bundle_pull_public_member_does_not_expose_private_sibling():
    config = SyncConfig(version=1, collections=[
        CollectionConfig(name="pub", storagePath="shared/data", readRoles=["public"], writeRoles=["admin"], encryption="none", maxBodyBytes=65536, bundle="sb"),
        CollectionConfig(name="priv", storagePath="shared/data", readRoles=["admin"], writeRoles=["admin"], encryption="none", maxBodyBytes=65536, bundle="sb"),
    ])
    store = MemoryObjectStore()
    seed = _app_for(store, config, "admin-1", ["admin"])
    assert await _push(seed, "/push/shared/data/pub", {"news": "hi"}) == 200
    assert await _push(seed, "/push/shared/data/priv", {"secret": "x"}) == 200

    anon = _app_for(store, config, "", ["public"])
    async with AsyncClient(transport=ASGITransport(app=anon), base_url="http://test") as client:
        resp = await client.get("/pull/shared/data")
    assert resp.status_code == 200
    body = resp.json()
    assert body["collections"]["pub"]["data"] == {"news": "hi"}
    assert "priv" not in body["collections"]  # private sibling NOT exposed to anonymous


@pytest.mark.asyncio
async def test_bundle_push_enforces_field_write_permissions():
    config = SyncConfig(version=1, collections=[
        CollectionConfig(name="doc", storagePath="users/{identity}/data", readRoles=["self"], writeRoles=["self"], encryption="none", maxBodyBytes=65536, bundle="fb", fieldPermissions={"adminNote": FieldPermission(writeRoles=["admin"])}),
        CollectionConfig(name="other", storagePath="users/{identity}/data", readRoles=["self"], writeRoles=["self"], encryption="none", maxBodyBytes=65536, bundle="fb"),
    ])
    store = MemoryObjectStore()
    self_app = _app_for(store, config, "user-1", ["self"])
    assert await _push(self_app, "/push/users/user-1/data/doc", {"adminNote": "x"}) == 403


@pytest.mark.asyncio
async def test_bundle_pull_strips_unreadable_fields():
    config = SyncConfig(version=1, collections=[
        CollectionConfig(name="doc", storagePath="users/{identity}/data", readRoles=["self"], writeRoles=["self"], encryption="none", maxBodyBytes=65536, bundle="frb", fieldPermissions={"ssn": FieldPermission(readRoles=["admin"])}),
    ])
    store = MemoryObjectStore()
    seed = _app_for(store, config, "user-1", ["self", "admin"])
    assert await _push(seed, "/push/users/user-1/data/doc", {"name": "Bob", "ssn": "123"}) == 200

    self_app = _app_for(store, config, "user-1", ["self"])
    async with AsyncClient(transport=ASGITransport(app=self_app), base_url="http://test") as client:
        resp = await client.get("/pull/users/user-1/data")
    body = resp.json()
    assert body["collections"]["doc"]["data"]["name"] == "Bob"
    assert "ssn" not in body["collections"]["doc"]["data"]  # admin-only field stripped on bundle pull


@pytest.mark.asyncio
async def test_proxied_push_through_write_is_audited():
    # A push the plugin proxies to a primary (interceptPush "respond") must still
    # appear in the audit log even though it never writes the local store.
    from starfish_protocol.plugins import ServerPlugin, PushHookResult
    from starfish_protocol.audit import AuditLogger, AuditEntry

    class _CollectingAudit(AuditLogger):
        def __init__(self) -> None:
            self.records: list[AuditEntry] = []

        async def record(self, entry: AuditEntry) -> None:
            self.records.append(entry)

    audit = _CollectingAudit()

    def _intercept(ctx) -> PushHookResult:
        return PushHookResult(action="respond", status=200, body={"hash": "primary-hash", "timestamp": 5})

    plugin = ServerPlugin(name="proxy", intercept_push=_intercept)

    config = SyncConfig(version=1, collections=[
        CollectionConfig(name="data", storagePath="users/{identity}/data", readRoles=["self"], writeRoles=["self"], encryption="none", maxBodyBytes=65536),
    ])
    store = MemoryObjectStore()

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["self"])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver, plugins=[plugin], audit_logger=audit)
    )
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/user-1/data",
            json={"data": {"x": 1}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 200
    push_records = [r for r in audit.records if r.action == "push" and r.collection == "data"]
    assert len(push_records) == 1
    assert push_records[0].success is True
    assert push_records[0].status_code == 200


# ---------------------------------------------------------------------------
# interceptPull dispatch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_intercept_pull_hook_serves_binary_response():
    """A plugin that returns action='respond' from intercept_pull is used as the
    HTTP response body, bypassing the normal JSON pull logic."""
    from starfish_protocol.plugins import ServerPlugin, InterceptPullResult

    parquet_magic = b"PAR1" + b"\x00" * 4  # minimal fake Parquet marker

    def _intercept_pull(ctx) -> InterceptPullResult:
        if ctx.collection != "docs":
            return InterceptPullResult(action="proceed")
        return InterceptPullResult(
            action="respond",
            status=200,
            body=parquet_magic,
            content_type="application/octet-stream",
        )

    plugin = ServerPlugin(name="binary-test", intercept_pull=_intercept_pull)

    config = SyncConfig(version=1, collections=[
        CollectionConfig(
            name="docs",
            storagePath="docs/{id}",
            readRoles=["public"],
            writeRoles=["public"],
            encryption="none",
            maxBodyBytes=65536,
            allowedMimeTypes=["application/json"],
        ),
    ])
    store = MemoryObjectStore()

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=None, roles=["public"])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver, plugins=[plugin])
    )
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/docs/any-id")

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/octet-stream"
    assert resp.content[:4] == b"PAR1"


@pytest.mark.asyncio
async def test_intercept_pull_proceed_falls_through_to_json_pull():
    """A plugin returning action='proceed' lets the normal JSON pull path run."""
    from starfish_protocol.plugins import ServerPlugin, InterceptPullResult

    plugin = ServerPlugin(
        name="pass-through",
        intercept_pull=lambda _ctx: InterceptPullResult(action="proceed"),
    )

    config = SyncConfig(version=1, collections=[
        CollectionConfig(
            name="docs",
            storagePath="docs/{id}",
            readRoles=["public"],
            writeRoles=["public"],
            encryption="none",
            maxBodyBytes=65536,
            allowedMimeTypes=["application/json"],
        ),
    ])
    store = MemoryObjectStore()
    await store.put("docs/my-doc", '{"data":{"x":1},"hash":"abc","ts":1}', content_type="application/json")

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=None, roles=["public"])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver, plugins=[plugin])
    )
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/docs/my-doc")

    assert resp.status_code == 200
    body = resp.json()
    assert body["data"] == {"x": 1}
