"""FastAPI router builder for the Starfish sync protocol."""


import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Awaitable

import httpx
import jsonschema

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from starfish_server.storage.base import AbstractObjectStore
from starfish_server.config.schema import SyncConfig, CollectionConfig, SyncTrigger, WriteMode, CollectionRateLimitConfig
from starfish_server.encryption.encrypted_store import EncryptedObjectStore
from starfish_server.protocol.pull import pull
from starfish_server.router.helpers import (
    handle_sync_pull,
    handle_sync_push,
    validate_path_segment,
    SignatureVerifier,
)
from starfish_server.router.middleware import check_body_limit, RateLimiter
from starfish_server.router.mime import matches_allowed_mime, is_json_collection
from starfish_server.constants import (
    ROLE_PUBLIC,
    ROLE_SELF,
    OP_READ,
    OP_WRITE,
    ENCRYPTION_IDENTITY,
    ENCRYPTION_SERVER,
    ENCRYPTION_DELEGATED,
    ACTION_PULL,
    ACTION_PUSH,
    IDENTITY_PARAM,
    IDENTITY_KEY,
    QUERY_CHECKPOINT,
    HKDF_INFO_IDENTITY,
    HKDF_INFO_SERVER,
)

if TYPE_CHECKING:
    from starfish_server.replica.manager import ReplicaManager
    from starfish_server.replica.notifier import NotificationPublisher


@dataclass
class AuthResult:
    """Result of authenticating a request."""

    identity: str
    roles: list[str]


RoleResolver = Callable[[Request], Awaitable[AuthResult]]
RoleEnricher = Callable[[AuthResult, dict[str, str]], Awaitable[list[str]]]


@dataclass
class SyncRouterOptions:
    store: AbstractObjectStore
    config: SyncConfig
    role_resolver: RoleResolver
    role_enricher: RoleEnricher | None = None
    encryption_secret: str | None = None
    server_encryption_secret: str | None = None
    server_identity: str | None = None
    identity_encryption_info: str | None = None
    server_encryption_info: str | None = None
    signature_verifier: SignatureVerifier | None = None
    replica_manager: "ReplicaManager | None" = None
    notification_publisher: "NotificationPublisher | None" = None
    role_resolver_timeout: float = 5.0


def _validate_object_schema(data: dict, schema: dict) -> JSONResponse | None:
    """Validate *data* against a JSON Schema. Returns 400 on failure, else None."""
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as exc:
        detail: dict[str, Any] = {
            "error": f"Schema validation failed: {exc.message}",
            "path": list(exc.absolute_path),
            "validator": exc.validator,
        }
        return JSONResponse(detail, status_code=400)
    return None


def _build_rate_limiter(
    col_rl: CollectionRateLimitConfig | None,
    opts: SyncRouterOptions,
) -> RateLimiter | None:
    """Build a RateLimiter using per-collection overrides falling back to the global config."""
    if col_rl is None or opts.config.rate_limit is None:
        return None
    global_rl = opts.config.rate_limit
    return RateLimiter(
        window_ms=col_rl.window_ms if col_rl.window_ms is not None else global_rl.window_ms,
        max_requests=col_rl.max_requests if col_rl.max_requests is not None else global_rl.max_requests,
    )


def _to_route_path(action: str, storage_path: str) -> str:
    return f"/{action}/{storage_path}"


def _resolve_document_key(template: str, params: dict[str, str]) -> str:
    result = template
    for key, value in params.items():
        result = result.replace(f"{{{key}}}", value)
    return result


def _validate_all_params(params: dict[str, str]) -> bool:
    for value in params.values():
        if not validate_path_segment(value):
            return False
    return True


def _extract_path_params(storage_path: str, request_path: str, action: str) -> dict[str, str]:
    param_names = re.findall(r"\{(\w+)\}", storage_path)
    pattern_str = storage_path
    for name in param_names:
        pattern_str = pattern_str.replace(f"{{{name}}}", f"(?P<{name}>[^/]+)")
    prefix = f"/{action}/"
    path_after_prefix = request_path[len(prefix):] if request_path.startswith(prefix) else request_path
    match = re.match(pattern_str, path_after_prefix)
    if not match:
        return {}
    return match.groupdict()


async def _check_auth(
    col: CollectionConfig,
    operation: str,
    request: Request,
    params: dict[str, str],
    opts: SyncRouterOptions,
) -> tuple[str | None, JSONResponse | None]:
    """Check authorization. Returns (identity, error_response)."""
    required_roles = col.read_roles if operation == OP_READ else col.write_roles

    if ROLE_PUBLIC in required_roles:
        return None, None

    try:
        auth = await asyncio.wait_for(
            opts.role_resolver(request), timeout=opts.role_resolver_timeout
        )
    except asyncio.TimeoutError:
        return None, JSONResponse({"error": "Unauthorized"}, status_code=503)
    except Exception:
        return None, JSONResponse({"error": "Unauthorized"}, status_code=401)

    effective_roles = set(auth.roles)

    if IDENTITY_PARAM in col.storage_path:
        if params.get(IDENTITY_KEY) == auth.identity:
            effective_roles.add(ROLE_SELF)

    if opts.role_enricher:
        extra = await opts.role_enricher(auth, params)
        effective_roles.update(extra)

    has_access = any(r in effective_roles for r in required_roles)
    if not has_access:
        return auth.identity, JSONResponse({"error": "Forbidden"}, status_code=403)

    return auth.identity, None


def _resolve_store(
    col: CollectionConfig,
    base_store: AbstractObjectStore,
    params: dict[str, str],
    identity: str | None,
    opts: SyncRouterOptions,
) -> AbstractObjectStore:
    if col.encryption == ENCRYPTION_IDENTITY:
        if not opts.encryption_secret:
            raise RuntimeError(f'Collection "{col.name}" requires encryption_secret')
        salt = identity or params.get(IDENTITY_KEY, "")
        return EncryptedObjectStore(
            base_store,
            opts.encryption_secret,
            salt,
            opts.identity_encryption_info or HKDF_INFO_IDENTITY,
        )
    if col.encryption == ENCRYPTION_SERVER:
        if not opts.server_encryption_secret:
            raise RuntimeError(f'Collection "{col.name}" requires server_encryption_secret')
        if not opts.server_identity:
            raise RuntimeError(f'Collection "{col.name}" requires server_identity')
        return EncryptedObjectStore(
            base_store,
            opts.server_encryption_secret,
            opts.server_identity,
            opts.server_encryption_info or HKDF_INFO_SERVER,
        )
    return base_store


async def _proxy_push_to_primary(
    col: CollectionConfig,
    request: Request,
    replica_manager: "ReplicaManager",
) -> JSONResponse:
    remote = col.remote  # type: ignore[union-attr]
    primary_url = f"{remote.url.rstrip('/')}{remote.push_path}"

    raw_body = await request.body()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        **remote.headers,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.post(primary_url, content=raw_body, headers=headers)
        except httpx.HTTPError as exc:
            return JSONResponse(
                {"error": f"Failed to reach primary: {exc}"},
                status_code=502,
            )

    if resp.status_code == 409:
        return JSONResponse({"error": "hash_mismatch"}, status_code=409)
    if not resp.is_success:
        return JSONResponse(
            {"error": f"Primary returned {resp.status_code}"},
            status_code=resp.status_code,
        )

    asyncio.create_task(replica_manager.sync_now(col.name))

    return JSONResponse(resp.json(), status_code=resp.status_code)


async def _run_push(
    request: Request,
    col: CollectionConfig,
    params: dict[str, str],
    document_key: str,
    identity: str | None,
    rate_limiter: RateLimiter | None,
    opts: SyncRouterOptions,
) -> JSONResponse:
    content_length = request.headers.get("content-length")
    limit_error = check_body_limit(content_length, col.max_body_bytes)
    if limit_error:
        return limit_error

    if rate_limiter:
        rate_error = rate_limiter.check(identity, request)
        if rate_error:
            return rate_error

    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type:
        return JSONResponse({"error": "Content-Type must be application/json"}, status_code=415)

    body = await request.json()
    if not isinstance(body, dict):
        return JSONResponse({"error": "Body must be a JSON object"}, status_code=400)

    if col.object_schema is not None:
        data = body.get("data")
        if isinstance(data, dict):
            schema_error = _validate_object_schema(data, col.object_schema)
            if schema_error:
                return schema_error

    store = _resolve_store(col, opts.store, params, identity, opts)
    is_client_encrypted = bool(col.client_encrypted) or col.encryption == ENCRYPTION_DELEGATED
    return await handle_sync_push(
        document_key, store, body, identity,
        opts.signature_verifier, is_client_encrypted,
    )


async def _run_binary_push(
    request: Request,
    col: CollectionConfig,
    document_key: str,
    identity: str | None,
    rate_limiter: RateLimiter | None,
    opts: SyncRouterOptions,
) -> Response:
    """Handle a binary push: validate MIME type, store raw bytes."""

    content_length = request.headers.get("content-length")
    limit_error = check_body_limit(content_length, col.max_body_bytes)
    if limit_error:
        return limit_error

    if rate_limiter:
        rate_error = rate_limiter.check(identity, request)
        if rate_error:
            return rate_error

    content_type = request.headers.get("content-type", "")
    if not matches_allowed_mime(content_type, col.allowed_mime_types):
        return JSONResponse(
            {"error": f"Content-Type '{content_type}' is not allowed. "
                      f"Allowed: {col.allowed_mime_types}"},
            status_code=415,
        )

    body = await request.body()
    content_hash = hashlib.sha256(body).hexdigest()

    media_type = content_type.split(";")[0].strip()
    await opts.store.put_bytes(document_key, body, content_type=media_type)

    return JSONResponse({"hash": content_hash})


def _make_push_handler(
    col: CollectionConfig,
    rate_limiter: RateLimiter | None,
    opts: SyncRouterOptions,
) -> Callable:
    """Create a push handler with *col* and *rate_limiter* captured in a closure.

    Returning the handler from a factory avoids exposing these as function
    parameters, which would cause FastAPI's dependency injection to re-create
    the instances on every request.
    """
    async def push_handler(request: Request) -> JSONResponse:
        params = request.path_params
        if not _validate_all_params(params):
            return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

        identity, error = await _check_auth(col, OP_WRITE, request, params, opts)
        if error:
            return error

        if (
            col.remote is not None
            and col.remote.write_mode == WriteMode.PUSH_THROUGH
            and opts.replica_manager is not None
        ):
            return await _proxy_push_to_primary(col, request, opts.replica_manager)

        if col.remote is not None and col.remote.write_mode == WriteMode.PULL_ONLY:
            return JSONResponse(
                {"error": "This collection is read-only on this server"},
                status_code=405,
            )

        document_key = _resolve_document_key(col.storage_path, params)

        if not is_json_collection(col.allowed_mime_types):
            return await _run_binary_push(
                request, col, document_key, identity, rate_limiter, opts,
            )

        response = await _run_push(request, col, params, document_key, identity, rate_limiter, opts)

        if opts.notification_publisher is not None and response.status_code == 200:
            resp_body = json.loads(response.body)
            asyncio.create_task(
                opts.notification_publisher.notify(
                    col.name, resp_body.get("hash", ""), resp_body.get("timestamp", 0)
                )
            )

        return response

    return push_handler


def _add_collection_routes(
    router: APIRouter,
    col: CollectionConfig,
    opts: SyncRouterOptions,
) -> None:
    if not col.push_only:
        pull_path = _to_route_path(ACTION_PULL, col.storage_path)

        async def pull_handler(request: Request, col=col) -> JSONResponse:
            params = request.path_params
            if not _validate_all_params(params):
                return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

            identity, error = await _check_auth(col, OP_READ, request, params, opts)
            if error:
                return error

            if col.remote is not None and col.remote.write_mode == WriteMode.PUSH_ONLY:
                return JSONResponse(
                    {"error": "This collection is write-only on this server"},
                    status_code=405,
                )

            if (
                opts.replica_manager is not None
                and col.remote is not None
                and SyncTrigger.ON_PULL in col.remote.sync_triggers
            ):
                await opts.replica_manager.on_pull(col.name)

            document_key = _resolve_document_key(col.storage_path, params)

            # Binary collection: return raw bytes
            if not is_json_collection(col.allowed_mime_types):
            
                result = await opts.store.get_bytes(document_key)
                if result is None:
                    return Response(status_code=404)
                raw_bytes, stored_content_type = result
                headers: dict[str, str] = {}
                headers["ETag"] = f'"{hashlib.sha256(raw_bytes).hexdigest()}"'
                if col.cache_duration_ms is not None:
                    max_age = col.cache_duration_ms // 1000
                    directive = (
                        f"max-age={max_age}"
                        if ROLE_PUBLIC in col.read_roles
                        else f"private, max-age={max_age}"
                    )
                    headers["Cache-Control"] = directive
                return Response(content=raw_bytes, media_type=stored_content_type, headers=headers)

            store = _resolve_store(col, opts.store, params, identity, opts)
            checkpoint_param = request.query_params.get(QUERY_CHECKPOINT)
            is_client_encrypted = bool(col.client_encrypted) or col.encryption == ENCRYPTION_DELEGATED
            return await handle_sync_pull(
                document_key, store, checkpoint_param,
                bool(col.force_full_fetch), is_client_encrypted,
                col.cache_duration_ms,
                is_public=ROLE_PUBLIC in col.read_roles,
            )

        router.add_api_route(pull_path, pull_handler, methods=["GET"])

    if not col.pull_only:
        push_path = _to_route_path(ACTION_PUSH, col.storage_path)
        rate_limiter = _build_rate_limiter(col.rate_limit, opts)
        router.add_api_route(
            push_path, _make_push_handler(col, rate_limiter, opts), methods=["POST"],
        )


def _add_bundled_routes(
    router: APIRouter,
    bundle_name: str,
    collections: list[CollectionConfig],
    opts: SyncRouterOptions,
) -> None:
    storage_path = collections[0].storage_path

    pull_path = _to_route_path(ACTION_PULL, storage_path)
    is_any_public = any(ROLE_PUBLIC in c.read_roles for c in collections)

    async def bundle_pull_handler(request: Request) -> JSONResponse:
        params = request.path_params
        if not _validate_all_params(params):
            return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

        if not is_any_public:
            identity, error = await _check_auth(collections[0], OP_READ, request, params, opts)
            if error:
                return error
        else:
            identity = None

        base_key = _resolve_document_key(storage_path, params)
        store = _resolve_store(collections[0], opts.store, params, identity, opts)

        any_client_encrypted = any(
            c.client_encrypted or c.encryption == ENCRYPTION_DELEGATED
            for c in collections
        )
        checkpoint_param = request.query_params.get(QUERY_CHECKPOINT)
        checkpoint = 0
        if not any_client_encrypted and checkpoint_param is not None:
            try:
                parsed = int(checkpoint_param)
            except ValueError:
                return JSONResponse({"error": "Invalid checkpoint"}, status_code=400)
            if parsed < 0 or str(parsed) != checkpoint_param:
                return JSONResponse({"error": "Invalid checkpoint"}, status_code=400)
            checkpoint = parsed

        result: dict[str, Any] = {}
        latest_timestamp = 0

        for col in collections:
            document_key = f"{base_key}/{col.name}"
            pull_result = await pull(store, document_key, checkpoint)
            result[col.name] = {
                "data": pull_result.data,
                "hash": pull_result.hash,
            }
            if pull_result.timestamp > latest_timestamp:
                latest_timestamp = pull_result.timestamp

        return JSONResponse({"collections": result, "timestamp": latest_timestamp})

    router.add_api_route(pull_path, bundle_pull_handler, methods=["GET"])

    for col in collections:
        if col.pull_only:
            continue

        push_path = _to_route_path(ACTION_PUSH, storage_path) + f"/{col.name}"
        rate_limiter = _build_rate_limiter(col.rate_limit, opts)

        def _make_bundle_push(col: CollectionConfig, rl: RateLimiter | None) -> Callable:
            async def bundle_push_handler(request: Request) -> JSONResponse:
                params = request.path_params
                if not _validate_all_params(params):
                    return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

                identity, error = await _check_auth(col, OP_WRITE, request, params, opts)
                if error:
                    return error

                document_key = f"{_resolve_document_key(storage_path, params)}/{col.name}"
                return await _run_push(request, col, params, document_key, identity, rl, opts)

            return bundle_push_handler

        router.add_api_route(push_path, _make_bundle_push(col, rate_limiter), methods=["POST"])


def create_sync_router(opts: SyncRouterOptions) -> APIRouter:
    """Create a FastAPI APIRouter with sync pull/push routes.

    CORS is not configured here — add CORSMiddleware to your FastAPI app if needed.
    Register ``await replica_manager.stop()`` in your app shutdown handler if using replicas.
    """
    router = APIRouter()
    config = opts.config

    @router.get("/health")
    async def health() -> dict:
        return {"ok": True, "ts": int(time.time() * 1000)}

    bundles: dict[str, list[CollectionConfig]] = {}
    standalone: list[CollectionConfig] = []

    for col in config.collections:
        if col.bundle:
            bundles.setdefault(col.bundle, []).append(col)
        else:
            standalone.append(col)

    for col in standalone:
        _add_collection_routes(router, col, opts)

    for bundle_name, bundle_collections in bundles.items():
        _add_bundled_routes(router, bundle_name, bundle_collections, opts)

    return router
