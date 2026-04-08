"""OpenAPI specification generator for Starfish sync routes."""

from __future__ import annotations

import re
from typing import Any

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.constants import ACTION_PULL, ACTION_PUSH, ROLE_PUBLIC


def generate_openapi_spec(
    config: SyncConfig,
    *,
    title: str = "Starfish Sync API",
    version: str = "1.0.0",
    server_url: str | None = None,
) -> dict[str, Any]:
    """Generate an OpenAPI 3.0 specification from a SyncConfig."""
    paths: dict[str, Any] = {}

    # Health endpoint
    paths["/health"] = {
        "get": {
            "summary": "Health check",
            "operationId": "health",
            "responses": {
                "200": {
                    "description": "Server is healthy",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"ok": {"type": "boolean"}, "ts": {"type": "number"}},
                            }
                        }
                    },
                }
            },
        }
    }

    for col in config.collections:
        if col.bundle:
            continue

        if not col.pull_only:
            pull_path = f"/{ACTION_PULL}/{col.storage_path}"
            paths[pull_path] = {"get": _build_pull_operation(col)}

        if not col.push_only:
            push_path = f"/{ACTION_PUSH}/{col.storage_path}"
            paths[push_path] = {"post": _build_push_operation(col)}

    spec: dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {"title": title, "version": version},
        "paths": paths,
        "components": {
            "schemas": {
                "PullResponse": {
                    "type": "object",
                    "properties": {
                        "data": {"type": "object"},
                        "hash": {"type": "string"},
                        "timestamp": {"type": "number"},
                    },
                    "required": ["data", "hash", "timestamp"],
                },
                "PushRequest": {
                    "type": "object",
                    "properties": {
                        "data": {"type": "object"},
                        "baseHash": {"type": "string", "nullable": True},
                        "authorSignature": {"type": "string"},
                    },
                    "required": ["data", "baseHash"],
                },
                "PushResponse": {
                    "type": "object",
                    "properties": {
                        "hash": {"type": "string"},
                        "timestamp": {"type": "number"},
                    },
                    "required": ["hash", "timestamp"],
                },
                "ErrorResponse": {
                    "type": "object",
                    "properties": {"error": {"type": "string"}},
                    "required": ["error"],
                },
            }
        },
    }

    if server_url:
        spec["servers"] = [{"url": server_url}]

    return spec


def _extract_path_params(storage_path: str) -> list[dict[str, Any]]:
    return [
        {"name": m, "in": "path", "required": True, "schema": {"type": "string"}}
        for m in re.findall(r"\{(\w+)\}", storage_path)
    ]


def _build_pull_operation(col: CollectionConfig) -> dict[str, Any]:
    is_public = ROLE_PUBLIC in col.read_roles
    params = _extract_path_params(col.storage_path)
    params.append({
        "name": "checkpoint", "in": "query", "required": False,
        "schema": {"type": "integer", "minimum": 0},
        "description": "Only return data updated after this timestamp",
    })

    op: dict[str, Any] = {
        "summary": f"Pull {col.name}",
        "operationId": f"pull_{col.name}",
        "parameters": params,
        "responses": {
            "200": {
                "description": "Sync data",
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PullResponse"}}},
            },
            "304": {"description": "Not Modified (ETag match)"},
            "400": {"description": "Invalid request"},
        },
    }
    if not is_public:
        op["responses"]["401"] = {"description": "Unauthorized"}
        op["responses"]["403"] = {"description": "Forbidden"}
        op["security"] = [{"bearerAuth": []}]
    return op


def _build_push_operation(col: CollectionConfig) -> dict[str, Any]:
    params = _extract_path_params(col.storage_path)
    return {
        "summary": f"Push {col.name}",
        "operationId": f"push_{col.name}",
        "parameters": params,
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PushRequest"}}},
        },
        "responses": {
            "200": {
                "description": "Push successful",
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PushResponse"}}},
            },
            "400": {"description": "Invalid request"},
            "401": {"description": "Unauthorized"},
            "403": {"description": "Forbidden"},
            "409": {"description": "Hash mismatch (conflict)"},
            "413": {"description": "Payload too large"},
            "415": {"description": "Unsupported content type"},
            "429": {"description": "Rate limit exceeded"},
        },
        "security": [{"bearerAuth": []}],
    }
