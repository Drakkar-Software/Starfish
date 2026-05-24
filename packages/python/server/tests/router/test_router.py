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
async def test_batch_pull_reports_parameterized_collections_explicitly():
    """A collection whose storage_path needs a `{param}` can't be batch-pulled.

    Batch pull resolves with no params, so the handler now reports such a collection
    with an explicit error instead of attempting a doomed store read on the literal
    template (which surfaced as a masked "Internal error"). A singleton collection in
    the same request is still served normally.
    """
    app, _ = _build_app(roles=["public"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/batch/pull?collections=settings,public-config")
    assert resp.status_code == 200
    cols = resp.json()["collections"]
    assert "data" not in cols["settings"]
    assert "not batch-pullable" in cols["settings"]["error"]
    assert "data" in cols["public-config"]  # singleton, reachable with the public role


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
    assert "data" in cols["public-config"]


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
    assert resp.json()["collections"]["ephemeral"]["data"] == {}  # expired → zeroed


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
