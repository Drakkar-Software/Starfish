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
    save_config,
)
from starfish_server.router import SyncRouterOptions, AuthResult, create_sync_router

store = FilesystemObjectStore(FilesystemStorageOptions(base_dir="./data"))

config = SyncConfig(
    version=1,
    collections=[
        CollectionConfig(
            name="settings",
            storage_path="users/{identity}/settings",
            read_roles=["self"],
            write_roles=["self"],
            encryption="none",
            max_body_bytes=65536,
        ),
        CollectionConfig(
            name="notes",
            storage_path="users/{identity}/notes",
            read_roles=["self"],
            write_roles=["self"],
            encryption="identity",  # per-user server-side encryption
            max_body_bytes=131072,
        ),
        CollectionConfig(
            name="posts",
            storage_path="posts/{postId}",
            read_roles=["public"],
            write_roles=["admin"],
            encryption="none",
            max_body_bytes=65536,
        ),
    ],
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
    )
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Persist config to storage so it can be reloaded later
    await save_config(store, config)
    yield


app = FastAPI(lifespan=lifespan)
app.include_router(sync_router, prefix="/v1")
