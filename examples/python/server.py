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
)
from starfish_server.router import SyncRouterOptions, AuthResult, create_sync_router

store = FilesystemObjectStore(FilesystemStorageOptions(base_dir="./data"))


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


sync_router = create_sync_router(
    SyncRouterOptions(
        store=store,
        config=config,
        role_resolver=role_resolver,
        encryption_secret=os.environ.get("ENCRYPTION_SECRET", "change-me"),
        # Grant "group-member" to users whose identity appears in groups/{groupId}/members
        role_enricher=create_group_role_enricher(
            GroupRoleEnricherOptions(
                store=store,
                members_path="groups/{groupId}/members",
                group_param="groupId",
            )
        ),
    )
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Persist config to storage so it can be reloaded later
    await save_config(store, config)
    yield


app = FastAPI(lifespan=lifespan)
app.include_router(sync_router, prefix="/v1")
