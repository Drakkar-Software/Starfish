"""
Basic Starfish server using FastAPI and filesystem storage.

Install:
    pip install starfish-server fastapi uvicorn

Run:
    uvicorn server:app --reload
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from starfish_server import (
    FilesystemObjectStore,
    FilesystemStorageOptions,
    SyncConfig,
    CollectionConfig,
    NamespaceConfig,
    save_config,
    create_group_role_enricher,
    GroupRoleEnricherOptions,
    create_entitlement_role_enricher,
    EntitlementRoleEnricherOptions,
    compose_enrichers,
)
from starfish_server.audit import CallbackAuditLogger, AuditEntry
from starfish_server.lifecycle import GracefulShutdown, GracefulShutdownOptions
from starfish_server.router import SyncRouterOptions, AuthResult, create_sync_router

store = FilesystemObjectStore(FilesystemStorageOptions(base_dir="./data"))

# For production: swap FilesystemObjectStore for S3ObjectStore
# (requires: pip install starfish-server[s3])
#
# from starfish_server.storage.s3 import S3ObjectStore, S3StorageOptions
# store = S3ObjectStore(S3StorageOptions(
#     access_key_id=os.environ["S3_ACCESS_KEY_ID"],
#     secret_access_key=os.environ["S3_SECRET_ACCESS_KEY"],
#     endpoint=os.environ.get("S3_ENDPOINT", "https://s3.amazonaws.com"),
#     bucket=os.environ["S3_BUCKET"],
#     region=os.environ.get("S3_REGION", "us-east-1"),
# ))


def _make_tenant_namespace(tenant_id: str) -> NamespaceConfig:
    """Create a namespace for a single tenant with a per-tenant storagePath prefix."""
    return NamespaceConfig(
        collections=[
            CollectionConfig(
                name="settings",
                # Prefix the storagePath with the tenant id to achieve true storage isolation.
                storage_path=f"{tenant_id}/users/{{identity}}/settings",
                read_roles=["self"],
                write_roles=["self"],
                encryption="none",
                max_body_bytes=65_536,
            ),
            CollectionConfig(
                name="notes",
                storage_path=f"{tenant_id}/users/{{identity}}/notes",
                read_roles=["self"],
                write_roles=["self"],
                encryption="identity",  # per-user server-side encryption
                max_body_bytes=131_072,
            ),
        ],
    )


config = SyncConfig(
    version=1,
    # Root-level collections are accessible at /pull/… and /push/…
    collections=[
        CollectionConfig(
            name="posts",
            storage_path="posts/{postId}",
            read_roles=["public"],
            write_roles=["admin"],
            encryption="none",
            max_body_bytes=65_536,
        ),

        # Group keyring — plaintext, admin-write, member-read.
        # Contains per-member ECDH-wrapped copies of the Group Encryption Key.
        CollectionConfig(
            name="keyring",
            storage_path="groups/{groupId}/keyring",
            read_roles=["group-member"],
            write_roles=["group-admin"],
            encryption="none",
            max_body_bytes=65_536,
        ),

        # Encrypted group chat — one document per group per day.
        # encryption="group" means the server stores opaque ciphertext;
        # clients use create_group_encryptor() to encrypt/decrypt.
        CollectionConfig(
            name="chat",
            storage_path="groups/{groupId}/chat/{day}",
            read_roles=["group-member"],
            write_roles=["group-member"],
            encryption="group",
            max_body_bytes=524_288,
            listable=True,
        ),

        # Group membership roster — read/written by group admins.
        # The role_enricher below reads this to grant "group-member".
        CollectionConfig(
            name="group-members",
            storage_path="groups/{groupId}/members",
            read_roles=["group-admin"],
            write_roles=["group-admin"],
            encryption="none",
            max_body_bytes=65_536,
        ),

        # Per-user entitlement document — admin writes, user reads their own.
        # Contains feature slugs like ["premium-package-1", "paid-cloud-sync"].
        # The entitlement_enricher below translates these into roles at request time.
        CollectionConfig(
            name="entitlements",
            storage_path="users/{identity}/entitlements",
            read_roles=["self"],
            write_roles=["admin"],
            encryption="none",
            max_body_bytes=4096,
        ),
        # Premium-gated collection — only users with the "premium-package-1" entitlement
        # can read this. Add to or remove from the user's entitlement document to grant/revoke.
        CollectionConfig(
            name="premium-content",
            storage_path="premium/{contentId}",
            read_roles=["entitlement:premium-package-1"],
            write_roles=["admin"],
            encryption="none",
            max_body_bytes=131_072,
        ),

        # Owner-managed whitelist — only the owner controls who can access the
        # restricted collection below. "self" is auto-granted when {ownerId} in
        # the storage_path matches the authenticated user's identity.
        # No encryption: this is pure RBAC — group encryption is not required.
        CollectionConfig(
            name="whitelist",
            storage_path="owners/{ownerId}/whitelist",
            read_roles=["self"],   # only the owner can read their own whitelist
            write_roles=["self"],  # only the owner can update their own whitelist
            encryption="none",
            max_body_bytes=65_536,
        ),
        # Restricted data — only users listed in the owner's whitelist can access.
        # The whitelist_enricher below grants "whitelisted" based on that document.
        CollectionConfig(
            name="restricted",
            storage_path="owners/{ownerId}/restricted",
            read_roles=["whitelisted"],
            write_roles=["whitelisted"],
            encryption="none",
            max_body_bytes=1_048_576,
        ),
    ],
    # Namespaced collections are accessible at /{tenant}/pull/… and /{tenant}/push/…
    # Each tenant gets its own storagePath prefix → full storage isolation.
    namespaces={
        "acme": _make_tenant_namespace("acme"),
        "globex": _make_tenant_namespace("globex"),
    },
)


async def role_resolver(request: Request) -> AuthResult:
    token = request.headers.get("authorization", "")
    # Replace with real auth logic (JWT, API key, etc.)
    if token.startswith("Bearer "):
        user_id = token.removeprefix("Bearer ")
        return AuthResult(identity=user_id, roles=["user"])
    return AuthResult(identity="anonymous", roles=["public"])


# Grant "group-member" to users listed in groups/{groupId}/members
group_enricher = create_group_role_enricher(
    GroupRoleEnricherOptions(
        store=store,
        members_path="groups/{groupId}/members",
        group_param="groupId",
    )
)

# Grant "whitelisted" to users listed in owners/{ownerId}/whitelist
whitelist_enricher = create_group_role_enricher(
    GroupRoleEnricherOptions(
        store=store,
        members_path="owners/{ownerId}/whitelist",
        group_param="ownerId",
        role="whitelisted",
    )
)

# Translate per-user entitlement slugs → roles like "entitlement:premium-package-1"
# Reads from users/{identity}/entitlements (default path)
entitlement_enricher = create_entitlement_role_enricher(
    EntitlementRoleEnricherOptions(store=store)
)

# Compose all enrichers: roles from all are merged into the effective set
role_enricher = compose_enrichers(group_enricher, whitelist_enricher, entitlement_enricher)


async def _audit_record(entry: AuditEntry) -> None:
    """Log only failed requests; swap for a DB write in production."""
    if not entry.success:
        print(
            f"[AUDIT] {entry.action.upper()} {entry.collection} "
            f"by {entry.identity or 'anonymous'} → {entry.status_code}"
        )


sync_router = create_sync_router(
    SyncRouterOptions(
        store=store,
        config=config,
        role_resolver=role_resolver,
        encryption_secret=os.environ.get("ENCRYPTION_SECRET", "change-me"),
        role_enricher=role_enricher,
        # Audit every pull and push — replace CallbackAuditLogger with a DB writer in prod
        audit=CallbackAuditLogger(_audit_record),
    )
)

shutdown = GracefulShutdown()  # handles SIGTERM / SIGINT; add replica_manager= or queue= if needed


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Persist config to storage so it can be reloaded later
    await save_config(store, config)
    shutdown.register()
    yield
    await shutdown.shutdown()


app = FastAPI(lifespan=lifespan)
app.include_router(sync_router, prefix="/v1")
