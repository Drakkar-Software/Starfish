"""
Starfish Parquet / DuckDB example (Python).

Demonstrates:
  1. Configuring a server with a Parquet collection (public read, authed write).
  2. Pushing a Parquet file from the client via push_parquet().
  3. Generating the DuckDB SQL to query the stored Parquet from S3.

Run (in-memory store, no real S3 needed for the push demo):
  python examples/python/parquet_duckdb.py

For real S3/MinIO, swap MemoryObjectStore for S3ObjectStore (see comment below).
"""

import asyncio
import hashlib
import json

from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server import (
    SyncConfig,
    MemoryObjectStore,
    create_parquet_collection,
    duckdb_read_parquet_sql,
    resolve_document_key,
    create_cap_cert_role_resolver,
    create_in_memory_nonce_cache,
    create_in_memory_revocation_store,
    PARQUET_MIME_TYPE,
)
from starfish_server.router import SyncRouterOptions, create_sync_router

# ── S3 options (swap MemoryObjectStore for S3ObjectStore in production) ────────
#
# To use real S3/MinIO:
#   from starfish_server.storage.s3 import S3ObjectStore, S3StorageOptions
#   s3_opts = S3StorageOptions(
#       endpoint="http://localhost:9000",
#       bucket="starfish",
#       access_key_id="minio",
#       secret_access_key="minio123",
#   )
#   store = S3ObjectStore(s3_opts)
from starfish_server.storage.s3 import S3StorageOptions

S3_OPTS = S3StorageOptions(
    endpoint="http://localhost:9000",
    bucket="starfish",
    access_key_id="minio",
    secret_access_key="minio123",
)

store = MemoryObjectStore(data={})


# ── Parquet collection ─────────────────────────────────────────────────────────
#
# create_parquet_collection() builds a CollectionConfig preset for
# DuckDB-readable Parquet files:
#   • allowed_mime_types = PARQUET_MIME_TYPES (accepts all common Parquet MIME variants)
#   • encryption: "none"  (delegated encryption stores ciphertext; DuckDB can't decode it)
#   • listable: True      (last storage_path segment is {dataset} → DuckDB can glob *.parquet)
#
# Auth levers (each independent):
#   read="public"         → anonymous DuckDB S3 reads bypass the server
#   read="authenticated"  → only cap-cert holders may pull
#   read="none"           → pull endpoint disabled (write-only ingest)
#   write="authenticated" → cap-cert required to push Parquet files
#   write="public"        → anyone can push (open ingest)
#   write=["role1", ...]  → custom role list

col = create_parquet_collection(
    name="datasets",
    storage_path="datasets/{owner}/{dataset}",
    read="public",          # DuckDB reads directly from S3 — no auth needed
    write="authenticated",  # Only cap-cert holders may push Parquet files
    rate_limit="none",      # No rate limit (default)
    max_body_bytes=256 * 1024 * 1024,
)

print("Collection config:")
print(json.dumps(col.model_dump(by_alias=True, exclude_none=True), indent=2))


# ── Server ─────────────────────────────────────────────────────────────────────

async def _role_resolver(request: Request):
    # In production: use create_cap_cert_role_resolver with a nonce cache +
    # revocation store. For this demo we return a minimal public identity.
    from starfish_server.router.route_builder import AuthResult
    return AuthResult(identity="", roles=["public"])


def build_app():
    config = SyncConfig(version=1, collections=[col])
    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=_role_resolver)
    )
    app = FastAPI()
    app.include_router(router)
    return app


# ── Tiny fake Parquet buffer (replace with your parquet library output) ─────────
# A valid Parquet file starts and ends with the magic bytes b"PAR1".
# In production, use a library like pyarrow, polars, or duckdb itself to
# generate real Parquet bytes from your data.
def make_parquet_bytes(label: str) -> bytes:
    magic = b"PAR1"
    body = f"FAKE_PARQUET_BODY:{label}".encode()
    return magic + body + magic


# ── Demo ────────────────────────────────────────────────────────────────────────

async def demo():
    parquet_bytes = make_parquet_bytes("q1-2024")
    app = build_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http:
        # Attempt a push. Without a real cap-cert this returns 403 (authed write).
        # In production, use StarfishClient.push_parquet() with a cap_provider.
        push_resp = await http.post(
            "/push/datasets/alice/q1-2024.parquet",
            content=parquet_bytes,
            headers={"content-type": PARQUET_MIME_TYPE},
        )

        if push_resp.status_code == 200:
            result = push_resp.json()
            print(f"\n✓ Pushed Parquet file. SHA-256 hash: {result['hash']}")
        else:
            print(f"\nPush status: {push_resp.status_code} (403 expected without cap-cert auth)")
            print("\n─── TIP ──────────────────────────────────────────────────────")
            print("Use StarfishClient.push_parquet() with a cap_provider for real auth:")
            print("  async with StarfishClient(base_url, auth=cap_provider) as client:")
            print("      await client.push_parquet('/push/datasets/alice/q1-2024.parquet', data)")
            print("──────────────────────────────────────────────────────────────\n")

    # ── Derive the S3 key and generate DuckDB SQL ──────────────────────────────
    #
    # resolve_document_key() maps the storage_path template + params to the
    # exact S3 object key (same key the server uses in put_bytes(key, bytes)).
    key = resolve_document_key("datasets/{owner}/{dataset}", {
        "owner": "alice",
        "dataset": "q1-2024.parquet",
    })
    print(f"\n── S3 key: {key}")

    # duckdb_read_parquet_sql() generates all the DuckDB SQL you need:
    result = duckdb_read_parquet_sql(s3=S3_OPTS, key=key)
    print(f"\n── S3 URI: {result.uri}")
    print("\n── DuckDB SQL (run in DuckDB CLI, via the duckdb Python package, etc.):")
    print("─" * 60)
    print(result.sql)
    print("─" * 60)

    # ── Glob over all of alice's datasets ──────────────────────────────────────
    prefix_key = resolve_document_key("datasets/{owner}", {"owner": "alice"})
    glob_result = duckdb_read_parquet_sql(s3=S3_OPTS, key=prefix_key, glob=True)
    print("\n── Glob query (all datasets for alice):")
    print("─" * 60)
    print(glob_result.sql)
    print("─" * 60)

    print("\nDone. In production:")
    print("  1. Run the server with S3ObjectStore (swap MemoryObjectStore above)")
    print("  2. Use StarfishClient.push_parquet() with a cap_provider for auth")
    print("  3. Run the generated DuckDB SQL to query the stored Parquet files")


if __name__ == "__main__":
    asyncio.run(demo())
