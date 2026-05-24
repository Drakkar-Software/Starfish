"""
Starfish v3.0 server using FastAPI and filesystem storage.

v3 changes vs. v2:
    • No `encryption_secret` on SyncRouterOptions — the server holds no keys.
    • Auth is cap-cert based: `create_cap_cert_role_resolver` + a nonce cache +
      a revocation store.
    • Collections use `encryption="none"` or `"delegated"` only.

Install:
    pip install starfish-server fastapi uvicorn

Run:
    uvicorn server:app --reload
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from starfish_server import (
    FilesystemObjectStore,
    FilesystemStorageOptions,
    SyncConfig,
    CollectionConfig,
    NamespaceConfig,
    save_config,
    create_cap_cert_role_resolver,
    create_in_memory_nonce_cache,
    create_in_memory_revocation_store,
    GracefulShutdown,
)
from starfish_audit import CallbackAuditLogger, AuditEntry
from starfish_identities import identities_server_plugin
from starfish_sharing import sharing_server_plugin
from starfish_server.router import SyncRouterOptions, create_sync_router


# ── Storage ─────────────────────────────────────────────────────────────────

store = FilesystemObjectStore(FilesystemStorageOptions(base_dir="./data"))

# For production: swap FilesystemObjectStore for S3ObjectStore
# (requires `pip install starfish-server[s3]`)
#
# from starfish_server.storage.s3 import S3ObjectStore, S3StorageOptions
# store = S3ObjectStore(S3StorageOptions(...))


# ── Collections — v3 encryption is "none" or "delegated" only. ──────────────


def _make_tenant_namespace(tenant_id: str) -> NamespaceConfig:
    return NamespaceConfig(
        collections=[
            CollectionConfig(
                name="settings",
                storage_path=f"{tenant_id}/users/{{identity}}/settings",
                read_roles=["cap:read:settings"],
                write_roles=["cap:write:settings"],
                encryption="none",
                max_body_bytes=65_536,
            ),
        ],
    )


config = SyncConfig(
    version=1,
    collections=[
        # Public-read posts.
        CollectionConfig(
            name="posts",
            storage_path="posts/{postId}",
            read_roles=["public"],
            write_roles=["cap:write:posts"],
            encryption="none",
            max_body_bytes=65_536,
        ),
        # Per-user notes — server stores opaque ciphertext, clients use
        # createKeyringEncryptor() to read/write.
        CollectionConfig(
            name="notes",
            storage_path="users/{identity}/notes",
            read_roles=["cap:read:notes"],
            write_roles=["cap:write:notes"],
            encryption="delegated",
            max_body_bytes=131_072,
        ),
        # The keyring document is plaintext but read-restricted to recipients.
        CollectionConfig(
            name="notes-keyring",
            storage_path="users/{identity}/notes/_keyring",
            read_roles=["cap:read:notes"],
            write_roles=["cap:write:notes"],
            encryption="none",
            max_body_bytes=65_536,
        ),
        # Shared-team — encrypted under a multi-recipient keyring.
        CollectionConfig(
            name="shared-team",
            storage_path="shared-team/{docId}",
            read_roles=["cap:read:shared-team"],
            write_roles=["cap:write:shared-team"],
            encryption="delegated",
            max_body_bytes=524_288,
            listable=True,
        ),
        CollectionConfig(
            name="shared-team-keyring",
            storage_path="shared-team/_keyring",
            read_roles=["cap:read:shared-team"],
            write_roles=["cap:write:shared-team"],
            encryption="none",
            max_body_bytes=65_536,
        ),
        # Per-user entitlement document.
        CollectionConfig(
            name="entitlements",
            storage_path="users/{identity}/entitlements",
            read_roles=["cap:read:entitlements"],
            write_roles=["cap:write:entitlements"],
            encryption="none",
            max_body_bytes=4096,
        ),
        # Plaintext, cap-only shared collection (no keyring). An alternative to
        # the encrypted "shared-team" above for data that does NOT need E2E
        # encryption: access is authorized purely by signed member caps + expiry
        # (the same mechanism as devices). The owner mints member caps with
        # `mint_member_cap` and either forwards them out-of-band or publishes
        # them into the `_members` list below, from which members fetch their
        # own with `fetch_my_member_cap`.
        CollectionConfig(
            name="shared-board",
            storage_path="shared-board/{docId}",
            read_roles=["cap:read:shared-board"],
            write_roles=["cap:write:shared-board"],
            encryption="none",
            max_body_bytes=524_288,
            listable=True,
        ),
        # Cap list: ALL members' full signed caps in one document. Read-open so a
        # member fetches their own cap without it being forwarded; owner-only
        # writes. `public` read is safe — a cap is usable only by the holder of
        # its subject private key (the server verifies each request against
        # `cert.sub`), so a readable roster never lets one member act as another.
        # Member caps cannot WRITE here: their scope denies `<col>/_members`.
        CollectionConfig(
            name="shared-board-members",
            storage_path="shared-board/_members",
            read_roles=["public"],
            write_roles=["cap:write:shared-board"],
            encryption="none",
            max_body_bytes=262_144,
        ),
    ],
    namespaces={
        "acme": _make_tenant_namespace("acme"),
        "globex": _make_tenant_namespace("globex"),
    },
)


# ── Cap-cert role resolver ──────────────────────────────────────────────────
#
# Replaces the v2 Bearer-token resolver. The resolver:
#   1. parses `Authorization: Cap <base64>`
#   2. verifies the cap-cert signature, nbf/exp, well-formedness
#   3. verifies `X-Starfish-Sig` over the request body and URL
#   4. consults the nonce cache (replay protection)
#   5. consults the revocation store
#   6. synthesizes roles like `cap:<op>:<collection>`

nonce_cache = create_in_memory_nonce_cache(
    window_ms=5 * 60_000,  # ±5-minute replay window — matches protocol skew
    max_entries=100_000,
)

revocation_store = create_in_memory_revocation_store()
# In production, persist revocations: rebuild this store from your DB at
# startup and call `revocation_store.revoke(iss, sub, nonce)` whenever an
# admin revokes a device or member cap.

role_resolver = create_cap_cert_role_resolver(
    nonce_cache=nonce_cache,
    revocation_store=revocation_store,
    # When False, requests without `Authorization: Cap` are rejected with 401.
    # Leave at True to allow public-read collections.
    allow_anonymous=True,
    # The resolver is secure-by-default: with no plugins it accepts only `device`
    # caps. Wire `identities_server_plugin` (device) + `sharing_server_plugin`
    # (member, enforces the member-cap shape barriers incl. the `_keyring` deny)
    # for the kinds this deployment issues.
    plugins=[identities_server_plugin, sharing_server_plugin],
)


# ── Audit logger ────────────────────────────────────────────────────────────


async def _audit_record(entry: AuditEntry) -> None:
    if not entry.success:
        print(
            f"[AUDIT] {entry.action.upper()} {entry.collection} "
            f"by {entry.identity or 'anonymous'} -> {entry.status_code}"
        )


# ── Router ──────────────────────────────────────────────────────────────────

sync_router = create_sync_router(
    SyncRouterOptions(
        store=store,
        config=config,
        role_resolver=role_resolver,
        audit_logger=CallbackAuditLogger(_audit_record),
    )
)

shutdown = GracefulShutdown()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await save_config(store, config)
    shutdown.register()
    yield
    await shutdown.shutdown()


app = FastAPI(lifespan=lifespan)
app.include_router(sync_router, prefix="/v1")
