"""Tests for per-collection objectSchema validation on push."""

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import (
    SyncConfig,
    CollectionConfig,
)
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from tests.helpers import MemoryObjectStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_app(
    collections: list[CollectionConfig],
    identity: str = "user-1",
    roles: list[str] | None = None,
) -> tuple[FastAPI, MemoryObjectStore]:
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=collections,
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=roles or [])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


async def _push(client: AsyncClient, path: str, data: dict | None = None, base_hash=None):
    """Push helper that returns the response."""
    resp = await client.post(
        path,
        json={"data": data or {"v": 1}, "baseHash": base_hash},
        headers={"content-type": "application/json"},
    )
    return resp


def _schema_col(schema: dict | None = None) -> CollectionConfig:
    return CollectionConfig(
        name="profiles",
        storagePath="users/{identity}/profiles",
        readRoles=["self"],
        writeRoles=["self"],
        encryption="none",
        maxBodyBytes=65536,
        objectSchema=schema,
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

USER_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer", "minimum": 0},
    },
    "required": ["name"],
    "additionalProperties": False,
}

NESTED_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "address": {
            "type": "object",
            "properties": {
                "street": {"type": "string"},
                "zip": {"type": "string", "pattern": "^[0-9]{5}$"},
            },
            "required": ["street", "zip"],
        },
        "tags": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
        },
    },
    "required": ["address"],
}

PROFILE_PATH = "/push/users/user-1/profiles"


# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------

class TestObjectSchemaConfig:
    """Schema field parsing on CollectionConfig."""

    def test_default_is_none(self):
        col = _schema_col()
        assert col.object_schema is None

    def test_set_via_alias(self):
        col = _schema_col(USER_SCHEMA)
        assert col.object_schema is not None
        assert col.object_schema["type"] == "object"
        assert "name" in col.object_schema["required"]

    def test_set_via_python_field_name(self):
        col = CollectionConfig(
            name="x",
            storagePath="x",
            readRoles=["self"],
            writeRoles=["self"],
            encryption="none",
            maxBodyBytes=1024,
            object_schema={"type": "object"},
        )
        assert col.object_schema == {"type": "object"}

    def test_complex_nested_schema_preserved(self):
        col = _schema_col(NESTED_SCHEMA)
        assert col.object_schema is not None
        assert "address" in col.object_schema["properties"]
        assert col.object_schema["properties"]["tags"]["minItems"] == 1


# ---------------------------------------------------------------------------
# Basic validation: flat schema
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_valid_push_accepted():
    """Push with data conforming to the schema succeeds."""
    app, _ = _build_app([_schema_col(USER_SCHEMA)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PROFILE_PATH, {"name": "Alice", "age": 30})
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_missing_required_field_rejected():
    """Push missing a required field is rejected with 400."""
    app, _ = _build_app([_schema_col(USER_SCHEMA)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PROFILE_PATH, {"age": 25})
        assert resp.status_code == 400
        assert "Schema validation failed" in resp.json()["error"]
        assert "'name'" in resp.json()["error"]


@pytest.mark.asyncio
async def test_wrong_type_rejected():
    """Push with wrong field type is rejected."""
    app, _ = _build_app([_schema_col(USER_SCHEMA)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PROFILE_PATH, {"name": "Alice", "age": "thirty"})
        assert resp.status_code == 400
        assert "Schema validation failed" in resp.json()["error"]


@pytest.mark.asyncio
async def test_additional_properties_rejected():
    """Push with extra properties rejected when additionalProperties: false."""
    app, _ = _build_app([_schema_col(USER_SCHEMA)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PROFILE_PATH, {"name": "Alice", "extra": True})
        assert resp.status_code == 400
        assert "Schema validation failed" in resp.json()["error"]


@pytest.mark.asyncio
async def test_empty_data_rejected_when_required_fields():
    """Empty data object is rejected when schema has required fields."""
    app, _ = _build_app([_schema_col(USER_SCHEMA)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PROFILE_PATH, {})
        assert resp.status_code == 400
        assert "Schema validation failed" in resp.json()["error"]


@pytest.mark.asyncio
async def test_minimum_value_rejected():
    """Push with value below minimum is rejected."""
    app, _ = _build_app([_schema_col(USER_SCHEMA)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PROFILE_PATH, {"name": "Alice", "age": -1})
        assert resp.status_code == 400
        assert "Schema validation failed" in resp.json()["error"]


@pytest.mark.asyncio
async def test_no_schema_allows_any_data():
    """Without a schema, any valid JSON object is accepted."""
    app, _ = _build_app([_schema_col(None)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PROFILE_PATH, {"anything": [1, 2, 3]})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Schema does not affect pull
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_does_not_affect_pull():
    """Pull always succeeds regardless of schema."""
    app, _ = _build_app([_schema_col(USER_SCHEMA)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PROFILE_PATH, {"name": "Alice"})
        assert resp.status_code == 200

        resp = await client.get("/pull/users/user-1/profiles")
        assert resp.status_code == 200
        assert resp.json()["data"]["name"] == "Alice"


# ---------------------------------------------------------------------------
# Updates (push with baseHash) also validate
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_also_validates():
    """Updates (push with baseHash) are validated against the schema too."""
    app, _ = _build_app([_schema_col(USER_SCHEMA)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # First push: valid
        resp = await _push(client, PROFILE_PATH, {"name": "Alice", "age": 30})
        assert resp.status_code == 200
        first_hash = resp.json()["hash"]

        # Update with valid data: accepted
        resp = await _push(client, PROFILE_PATH, {"name": "Bob", "age": 25}, first_hash)
        assert resp.status_code == 200
        second_hash = resp.json()["hash"]

        # Update with invalid data: rejected by schema (not conflict)
        resp = await _push(client, PROFILE_PATH, {"age": 25}, second_hash)
        assert resp.status_code == 400
        assert "Schema validation failed" in resp.json()["error"]


# ---------------------------------------------------------------------------
# Nested object & array validation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_nested_object_valid():
    """Nested objects that match the schema are accepted."""
    app, _ = _build_app([_schema_col(NESTED_SCHEMA)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PROFILE_PATH, {
            "address": {"street": "123 Main St", "zip": "90210"},
            "tags": ["vip"],
        })
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_nested_missing_required_rejected():
    """Nested object with missing required inner field is rejected."""
    app, _ = _build_app([_schema_col(NESTED_SCHEMA)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PROFILE_PATH, {
            "address": {"street": "123 Main St"},
        })
        assert resp.status_code == 400
        assert "Schema validation failed" in resp.json()["error"]


@pytest.mark.asyncio
async def test_pattern_rejected():
    """String that doesn't match a regex pattern is rejected."""
    app, _ = _build_app([_schema_col(NESTED_SCHEMA)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PROFILE_PATH, {
            "address": {"street": "123 Main St", "zip": "ABCDE"},
        })
        assert resp.status_code == 400
        assert "Schema validation failed" in resp.json()["error"]


@pytest.mark.asyncio
async def test_array_items_wrong_type_rejected():
    """Array with items of the wrong type is rejected."""
    app, _ = _build_app([_schema_col(NESTED_SCHEMA)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PROFILE_PATH, {
            "address": {"street": "123 Main St", "zip": "90210"},
            "tags": [123],
        })
        assert resp.status_code == 400
        assert "Schema validation failed" in resp.json()["error"]


@pytest.mark.asyncio
async def test_array_min_items_rejected():
    """Array with too few items is rejected."""
    app, _ = _build_app([_schema_col(NESTED_SCHEMA)])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PROFILE_PATH, {
            "address": {"street": "123 Main St", "zip": "90210"},
            "tags": [],
        })
        assert resp.status_code == 400
        assert "Schema validation failed" in resp.json()["error"]


# ---------------------------------------------------------------------------
# Multiple collections with different schemas
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_different_collections_different_schemas():
    """Two collections with different schemas validate independently."""
    strict_schema = {
        "type": "object",
        "properties": {"key": {"type": "string"}},
        "required": ["key"],
        "additionalProperties": False,
    }
    loose_schema = {
        "type": "object",
    }
    col_strict = CollectionConfig(
        name="strict",
        storagePath="users/{identity}/strict",
        readRoles=["self"],
        writeRoles=["self"],
        encryption="none",
        maxBodyBytes=65536,
        objectSchema=strict_schema,
    )
    col_loose = CollectionConfig(
        name="loose",
        storagePath="users/{identity}/loose",
        readRoles=["self"],
        writeRoles=["self"],
        encryption="none",
        maxBodyBytes=65536,
        objectSchema=loose_schema,
    )
    app, _ = _build_app([col_strict, col_loose])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Strict rejects extra properties
        resp = await _push(client, "/push/users/user-1/strict", {"key": "a", "extra": 1})
        assert resp.status_code == 400

        # Loose accepts anything
        resp = await _push(client, "/push/users/user-1/loose", {"key": "a", "extra": 1})
        assert resp.status_code == 200
