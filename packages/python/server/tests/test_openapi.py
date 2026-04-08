"""Tests for OpenAPI spec generation."""

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.openapi import generate_openapi_spec


def _make_config() -> SyncConfig:
    return SyncConfig(
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
    )


def test_generates_valid_spec():
    spec = generate_openapi_spec(_make_config())
    assert spec["openapi"] == "3.0.3"
    assert spec["info"]["title"] == "Starfish Sync API"


def test_includes_pull_and_push_paths():
    spec = generate_openapi_spec(_make_config())
    paths = spec["paths"]
    assert "/pull/users/{identity}/settings" in paths
    assert "/push/users/{identity}/settings" in paths
    assert "/pull/app/config" in paths


def test_includes_health_endpoint():
    spec = generate_openapi_spec(_make_config())
    assert "/health" in spec["paths"]


def test_includes_component_schemas():
    spec = generate_openapi_spec(_make_config())
    schemas = spec["components"]["schemas"]
    assert "PullResponse" in schemas
    assert "PushRequest" in schemas
    assert "PushResponse" in schemas


def test_custom_title_and_server():
    spec = generate_openapi_spec(
        _make_config(), title="My API", version="2.0", server_url="https://api.example.com",
    )
    assert spec["info"]["title"] == "My API"
    assert spec["servers"][0]["url"] == "https://api.example.com"
