"""OpenAPI specification generator for Starfish sync routes."""


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

    # Root collection paths
    for col in config.collections:
        if col.bundle:
            continue

        if not col.push_only:
            pull_path = f"/{ACTION_PULL}/{col.storage_path}"
            paths[pull_path] = {"get": _build_pull_operation(col)}

        if not col.pull_only:
            push_path = f"/{ACTION_PUSH}/{col.storage_path}"
            paths[push_path] = {"post": _build_push_operation(col)}

    # Root batch/pull
    paths["/batch/pull"] = _build_batch_pull_operation()

    # Namespace paths
    if config.namespaces:
        for ns_name, ns_config in config.namespaces.items():
            for col in ns_config.collections:
                if col.bundle:
                    continue

                if not col.push_only:
                    pull_path = f"/{ns_name}/{ACTION_PULL}/{col.storage_path}"
                    paths[pull_path] = {"get": _build_pull_operation(col, ns_name=ns_name)}

                if not col.pull_only:
                    push_path = f"/{ns_name}/{ACTION_PUSH}/{col.storage_path}"
                    paths[push_path] = {"post": _build_push_operation(col, ns_name=ns_name)}

            paths[f"/{ns_name}/batch/pull"] = _build_batch_pull_operation(ns_name=ns_name)

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


def _build_pull_operation(col: CollectionConfig, *, ns_name: str | None = None) -> dict[str, Any]:
    is_public = ROLE_PUBLIC in col.read_roles
    params = _extract_path_params(col.storage_path)
    params.append({
        "name": "checkpoint", "in": "query", "required": False,
        "schema": {"type": "integer", "minimum": 0},
        "description": "Only return data updated after this timestamp",
    })

    if ns_name is not None:
        operation_id = f"pull--{ns_name}--{col.name}"
    else:
        operation_id = f"pull_{col.name}"

    op: dict[str, Any] = {
        "summary": f"Pull {col.name}",
        "operationId": operation_id,
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


def _build_push_operation(col: CollectionConfig, *, ns_name: str | None = None) -> dict[str, Any]:
    params = _extract_path_params(col.storage_path)

    if ns_name is not None:
        operation_id = f"push--{ns_name}--{col.name}"
    else:
        operation_id = f"push_{col.name}"

    return {
        "summary": f"Push {col.name}",
        "operationId": operation_id,
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


def _build_batch_pull_operation(*, ns_name: str | None = None) -> dict[str, Any]:
    if ns_name is not None:
        operation_id = f"batch_pull--{ns_name}"
        summary = f"Batch pull ({ns_name})"
    else:
        operation_id = "batch_pull"
        summary = "Batch pull"

    return {
        "get": {
            "summary": summary,
            "operationId": operation_id,
            "parameters": [
                {
                    "name": "collections",
                    "in": "query",
                    "required": True,
                    "schema": {"type": "string"},
                    "description": "Comma-separated list of collection names to pull",
                }
            ],
            "responses": {
                "200": {
                    "description": "Batch pull results",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "collections": {
                                        "type": "object",
                                        "additionalProperties": {"$ref": "#/components/schemas/PullResponse"},
                                    }
                                },
                            }
                        }
                    },
                },
                "400": {"description": "Missing collections parameter"},
            },
        }
    }
