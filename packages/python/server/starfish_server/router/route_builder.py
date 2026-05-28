"""FastAPI router builder for the Starfish sync protocol."""


import asyncio
import logging
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

import jsonschema

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from starfish_server.storage.base import AbstractObjectStore, StoreContext
from starfish_server.config.schema import SyncConfig, CollectionConfig, CollectionRateLimitConfig, NamespaceConfig, ConfigEndpointOptions, AppendOnlyConfig
from starfish_server.protocol.pull import pull
from starfish_server.router.helpers import (
    handle_sync_pull,
    handle_sync_push,
    handle_append_only_pull,
    deep_sanitize,
    json_depth_within,
    validate_path_segment,
    is_unsafe_document_key,
    is_with_keyring_enabled,
)
from starfish_server.protocol.push import append_item, AppendConflict, AppendLimitExceeded
from starfish_server.protocol.types import PushSuccess
from starfish_protocol.hash import compute_hash
from starfish_protocol.append_author import verify_append_author
from starfish_protocol.constants import (
    AUTHOR_PUBKEY_FIELD,
    AUTHOR_SIGNATURE_FIELD,
    DATA_FIELD,
    TS_FIELD,
)
from starfish_server.router.middleware import check_body_limit, RateLimiter
from starfish_server.router.mime import matches_allowed_mime, is_json_collection
from starfish_server.router.cap_resolver import match_scope_path
from starfish_protocol.plugins import (
    PullHookContext,
    PushHookContext,
    ServerPlugin,
    WriteEvent,
)
from starfish_server.plugins import (
    dispatch_after_write,
    dispatch_before_pull,
    dispatch_intercept_push,
)
from starfish_server.ttl import is_expired as _is_expired
from starfish_protocol import AuditLogger, AuditEntry as _AuditEntry
from starfish_server.constants import (
    ROLE_PUBLIC,
    ROLE_ROOT_DEVICE,
    ROLE_SELF,
    OP_READ,
    OP_WRITE,
    ENCRYPTION_DELEGATED,
    ACTION_PULL,
    ACTION_PUSH,
    ACTION_LIST,
    IDENTITY_PARAM,
    IDENTITY_KEY,
    QUERY_CHECKPOINT,
    APPEND_DEFAULT_FIELD,
    APPEND_MAX_FUTURE_TS_SKEW_MS,
)

@dataclass(frozen=True)
class Presenter:
    """The verified request presenter: the Ed25519 public key that signed THIS
    request. Used to bind a signed append's ``authorPubkey`` to its authenticated
    writer so the stored author cannot be forged."""

    pub_hex: str


@dataclass
class AuthResult:
    """Result of authenticating a request."""

    identity: str
    roles: list[str]
    # Expanded cap-cert scope paths ({identity} already substituted), or None for
    # resolvers that carry no path scope (e.g. pure role-based auth). Used to
    # authorize the sibling ``_keyring`` read of the ?withKeyring=1 optimization.
    scope_paths: list[str] | None = None
    # The verified request presenter (set by the cap-cert resolver; None for a
    # pure role-based resolver that carries no per-request key). Used to bind a
    # signed append's author to its authenticated writer.
    presenter: "Presenter | None" = None


RoleResolver = Callable[[Request], Awaitable[AuthResult]]
# Derives extra roles from the authenticated ``AuthResult`` and the request
# params. MUST be idempotent and free of observable side effects: it can be
# invoked MORE THAN ONCE per request — the ``/batch/pull`` handler calls it once
# per requested collection (each with that collection's params) off a single auth
# resolve. (The replay-protected resolver runs once; the enricher does not
# consume the nonce.)
RoleEnricher = Callable[[AuthResult, dict[str, str]], Awaitable[list[str]]]


@dataclass
class SyncRouterOptions:
    store: AbstractObjectStore
    config: SyncConfig
    role_resolver: RoleResolver
    role_enricher: RoleEnricher | None = None
    plugins: list[ServerPlugin] | None = None
    role_resolver_timeout: float = 5.0
    config_endpoint: ConfigEndpointOptions | None = None
    audit_logger: AuditLogger | None = None
    # Max collections a single ``/batch/pull`` request may name. Bounds the
    # per-request work (store reads + enricher + scope checks) one signed request
    # can drive, since the rate limiter caps requests, not work-per-request.
    max_collections_per_batch: int = 100


from pydantic import BaseModel as _BaseModel


class CollectionClientInfo(_BaseModel):
    """Per-collection metadata returned by ``GET /config``."""

    name: str
    maxBodyBytes: int
    encryption: str
    allowedMimeTypes: list[str]
    pullOnly: bool | None = None
    pushOnly: bool | None = None
    appendOnly: AppendOnlyConfig | None = None
    ttlMs: int | None = None
    forceFullFetch: bool | None = None

    model_config = {"populate_by_name": True}


class _NamespaceClientInfo(_BaseModel):
    collections: list[CollectionClientInfo]


class ConfigResponse(_BaseModel):
    """Response shape of ``GET /config``."""

    collections: list[CollectionClientInfo]
    namespaces: dict[str, _NamespaceClientInfo] | None = None


def _to_collection_client_info(col: CollectionConfig) -> CollectionClientInfo:
    return CollectionClientInfo(
        name=col.name,
        maxBodyBytes=col.max_body_bytes,
        encryption=col.encryption,
        allowedMimeTypes=col.allowed_mime_types,
        pullOnly=col.pull_only or None,
        pushOnly=col.push_only or None,
        appendOnly=col.append_only or None,
        ttlMs=col.ttl_ms,
        forceFullFetch=col.force_full_fetch or None,
    )


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


_LIST_DEFAULT_LIMIT = 100
_LIST_MAX_LIMIT = 1000


def _to_route_path(action: str, storage_path: str) -> str:
    return f"/{action}/{storage_path}"


def _to_list_route_path(storage_path: str) -> str:
    """Derive the list route path by dropping the last path segment (the enumerated param)."""
    segments = storage_path.split("/")
    prefix_path = "/".join(segments[:-1])
    return _to_route_path(ACTION_LIST, prefix_path)


def _resolve_document_key(template: str, params: dict[str, str]) -> str:
    result = template
    for key, value in params.items():
        result = result.replace(f"{{{key}}}", value)
    return result


def _to_list_prefix(storage_path: str, params: dict[str, str]) -> str:
    """Resolve the storage key prefix for listKeys (storagePath without the last param)."""
    segments = storage_path.split("/")
    prefix_template = "/".join(segments[:-1])
    resolved = _resolve_document_key(prefix_template, params)
    return (resolved + "/") if resolved else ""


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


async def _resolve_base_auth(
    request: Request,
    opts: SyncRouterOptions,
) -> tuple[Any, str | None, set[str], JSONResponse | None]:
    """Run the role resolver ONCE and return ``(auth, identity, base_roles,
    error)`` WITHOUT folding in the per-collection ``self``/enricher roles.

    The resolver consumes the request nonce (replay protection) and must run at
    most once per request: a handler that authorizes many collections (bundle
    pull, batch pull) calls this once, then ``_fold_collection_roles`` per
    collection. Stashes the cap scope + presenter for downstream handlers.
    """
    try:
        auth = await asyncio.wait_for(
            opts.role_resolver(request), timeout=opts.role_resolver_timeout
        )
    except asyncio.TimeoutError:
        return None, None, set(), JSONResponse({"error": "Unauthorized"}, status_code=503)
    except Exception as exc:
        # Honour a resolver-supplied ``.status`` (used by CapAuthError to
        # signal 403 / 413 vs the default 401). Fall back to 401 otherwise.
        status = getattr(exc, "status", None)
        if status == 403:
            return None, None, set(), JSONResponse({"error": "Forbidden"}, status_code=403)
        if status == 413:
            message = str(exc) if str(exc) else "Payload too large"
            return None, None, set(), JSONResponse({"error": message}, status_code=413)
        logging.getLogger(__name__).error(
            "_resolve_base_auth: role_resolver raised: %s", exc, exc_info=True
        )
        return None, None, set(), JSONResponse({"error": "Unauthorized"}, status_code=401)

    # Stash the cap scope (if any) for sibling-read authorization downstream
    # (e.g. the ?withKeyring=1 keyring shortcut in the pull handler). None for
    # role-based resolvers that carry no path scope.
    request.state.cap_scope_paths = auth.scope_paths
    # Stash the verified request presenter (the key that signed this request) so
    # the append handler can bind a signed element's author to its writer. None
    # for a pure role-based resolver that carries no per-request key.
    request.state.presenter = auth.presenter

    return auth, auth.identity, set(auth.roles), None


async def _fold_collection_roles(
    auth: Any,
    base_roles: set[str],
    params: dict[str, str],
    storage_path: str,
    opts: SyncRouterOptions,
) -> tuple[frozenset[str], JSONResponse | None]:
    """Fold the conditional ``self`` role and any enricher roles into a COPY of
    the caller's base roles, for ONE collection's params + storage_path. Does NOT
    re-run the resolver (never re-consumes the nonce) — a multi-collection handler
    calls this once per collection with that collection's resolved params.
    """
    effective_roles: set[str] = set(base_roles)
    if IDENTITY_PARAM in storage_path:
        if params.get(IDENTITY_KEY) == auth.identity:
            effective_roles.add(ROLE_SELF)
    if opts.role_enricher:
        try:
            extra = await opts.role_enricher(auth, params)
            effective_roles.update(extra)
        except Exception as exc:
            logging.getLogger(__name__).error(
                "_fold_collection_roles: role_enricher raised: %s", exc, exc_info=True
            )
            return (
                frozenset(effective_roles),
                JSONResponse({"error": "Authorization error"}, status_code=500),
            )
    return frozenset(effective_roles), None


async def _resolve_effective_roles(
    request: Request,
    params: dict[str, str],
    opts: SyncRouterOptions,
    storage_path: str,
) -> tuple[str | None, frozenset[str], JSONResponse | None]:
    """Run the role resolver ONCE and fold in the conditional ``self`` role and
    any enricher roles. Returns ``(identity, effective_roles, error)`` without
    checking against a specific collection — callers do that themselves.

    Thin wrapper over ``_resolve_base_auth`` + ``_fold_collection_roles`` for the
    standalone and bundle pull paths (one params set); batch pull calls the two
    halves directly so it can fold per-collection params after a single resolve.
    """
    auth, identity, base_roles, error = await _resolve_base_auth(request, opts)
    if error is not None or auth is None:
        return identity, frozenset(base_roles), error
    roles, fold_error = await _fold_collection_roles(
        auth, base_roles, params, storage_path, opts
    )
    return identity, roles, fold_error


def _apply_field_read_filter(
    data: Any,
    field_permissions: Any,
    roles: frozenset[str] | set[str],
) -> None:
    """Strip fields the caller's roles cannot read from ``data``, in place.

    Shared by the standalone, bundle, and batch pull paths so field-read
    permissions are enforced identically everywhere (the bundle path previously
    skipped this, leaking restricted fields).
    """
    if not field_permissions or not isinstance(data, dict):
        return
    for field_name, fp in field_permissions.items():
        if fp.read_roles:
            has_access = any(r in roles or r == ROLE_PUBLIC for r in fp.read_roles)
            if not has_access:
                data.pop(field_name, None)


def _is_access_allowed(
    col: CollectionConfig,
    operation: str,
    effective_roles: frozenset[str] | set[str],
) -> bool:
    """The per-collection access decision shared by every authorized path
    (``_check_auth``, the bundle-pull handler).

    Centralizing it keeps ``rootOnly`` and the read/write role + public rules
    from drifting between call sites — a divergence would let one route enforce
    a rule another silently skips. ``rootOnly`` is an additive gate: the caller
    must hold ``ROLE_ROOT_DEVICE`` (a self-signed device cap) on top of the
    normal role check. Config validation forbids ``rootOnly`` + public, so a
    root-only collection never short-circuits on ``ROLE_PUBLIC`` here.
    """
    if col.root_only and ROLE_ROOT_DEVICE not in effective_roles:
        return False
    required_roles = col.read_roles if operation == OP_READ else col.write_roles
    if ROLE_PUBLIC in required_roles:
        return True
    return any(r in effective_roles for r in required_roles)


async def _check_auth(
    col: CollectionConfig,
    operation: str,
    request: Request,
    params: dict[str, str],
    opts: SyncRouterOptions,
) -> tuple[str | None, frozenset[str], JSONResponse | None]:
    """Check authorization. Returns (identity, effective_roles, error_response)."""
    required_roles = col.read_roles if operation == OP_READ else col.write_roles

    # A rootOnly collection is never public (enforced at config load), so it must
    # always resolve the caller's roles rather than short-circuit anonymous here.
    if not col.root_only and ROLE_PUBLIC in required_roles:
        return None, frozenset(), None

    async def _audit_denial(ident: str | None, err: JSONResponse) -> None:
        # Record auth-layer denials (401/403/…) so the trail is not blind to them —
        # otherwise only requests that reach the handler are ever logged.
        if opts.audit_logger is not None:
            await opts.audit_logger.record(_AuditEntry(
                timestamp=time.time() * 1000,
                action="pull" if operation == OP_READ else "push",
                collection=col.name,
                identity=ident,
                document_key="",
                success=False,
                status_code=err.status_code,
                params=dict(params),
            ))

    identity, effective_roles, error = await _resolve_effective_roles(
        request, params, opts, col.storage_path
    )
    if error:
        await _audit_denial(identity, error)
        return identity, effective_roles, error

    if not _is_access_allowed(col, operation, effective_roles):
        error = JSONResponse({"error": "Forbidden"}, status_code=403)
        await _audit_denial(identity, error)
        return identity, effective_roles, error

    return identity, effective_roles, None


async def _run_push(
    request: Request,
    col: CollectionConfig,
    params: dict[str, str],
    document_key: str,
    identity: str | None,
    effective_roles: frozenset[str],
    rate_limiter: RateLimiter | None,
    opts: SyncRouterOptions,
    context: StoreContext | None = None,
) -> JSONResponse:
    content_length = request.headers.get("content-length")
    limit_error = check_body_limit(content_length, col.max_body_bytes)
    if limit_error:
        return limit_error

    if rate_limiter:
        rate_error = rate_limiter.check(
            identity,
            request.headers.get("x-forwarded-for"),
            request.client.host if request.client else None,
        )
        if rate_error:
            return rate_error

    content_type = request.headers.get("content-type", "")
    if "application/json" not in content_type:
        return JSONResponse({"error": "Content-Type must be application/json"}, status_code=415)

    # Parse defensively: a deeply-nested body overflows the recursive JSON parser
    # (CPython) with `RecursionError`. The exception unwinds the deep parse frames
    # back to this shallow handler, so catching it here is safe — return 400 rather
    # than letting it surface as an unhandled 500.
    try:
        body = await request.json()
    except RecursionError:
        return JSONResponse({"error": "Body nesting too deep"}, status_code=400)
    except (ValueError, UnicodeDecodeError):
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "Body must be a JSON object"}, status_code=400)
    # Enforce a hard nesting bound (iteratively, so the check itself can't recurse)
    # before `deep_sanitize` walks the structure recursively.
    if not json_depth_within(body):
        return JSONResponse({"error": "Body nesting too deep"}, status_code=400)

    # Field-level write permission check
    if col.field_permissions and isinstance(body.get(DATA_FIELD), dict):
        for field_name, fp in col.field_permissions.items():
            if fp.write_roles and field_name in body["data"]:
                # `ROLE_PUBLIC` in a field's writeRoles means "unrestricted" — honor it
                # here exactly as the field-READ check (above) and the TS server do.
                if not any(r in effective_roles or r == ROLE_PUBLIC for r in fp.write_roles):
                    return JSONResponse(
                        {"error": f'Forbidden: field "{field_name}" requires roles: {", ".join(fp.write_roles)}'},
                        status_code=403,
                    )

    if col.object_schema is not None:
        data = body.get(DATA_FIELD)
        if isinstance(data, dict):
            schema_error = _validate_object_schema(data, col.object_schema)
            if schema_error:
                return schema_error

    store = opts.store
    is_client_encrypted = col.encryption == ENCRYPTION_DELEGATED

    if col.append_only:
        append_cfg = col.append_only
        append_field = append_cfg.field or APPEND_DEFAULT_FIELD

        # The element payload. Opaque to the server: plaintext under "none", an
        # encryptor wrapper under "delegated" (both are JSON objects).
        item = body.get(DATA_FIELD)
        if not isinstance(item, dict):
            return JSONResponse({"error": "Missing or invalid data"}, status_code=400)
        sanitized_item = deep_sanitize(item)

        # Append author proof. The signature is over the SANITIZED item — the exact
        # bytes stored — so a reader who pulls the element re-verifies the same data.
        # When ``require_author_signature`` is enforced (the default), a missing,
        # invalid, or forged proof is rejected here; the fields are then stored on
        # the element. An opt-out collection (``requireAuthorSignature: false``)
        # skips the check but still stores any proof the client sent.
        raw_author_pubkey = body.get(AUTHOR_PUBKEY_FIELD)
        raw_author_signature = body.get(AUTHOR_SIGNATURE_FIELD)
        author_pubkey = raw_author_pubkey if isinstance(raw_author_pubkey, str) else None
        author_signature = (
            raw_author_signature if isinstance(raw_author_signature, str) else None
        )
        if append_cfg.require_author_signature:
            if author_pubkey is None or author_signature is None:
                return JSONResponse(
                    {"error": "append requires authorPubkey and authorSignature"},
                    status_code=400,
                )
            # Bind the author to the authenticated caller: the signing key MUST be
            # the request presenter (cap subject / audience redeemer). A pure role
            # resolver carries no presenter — the signature is still required and
            # verified, but cannot be bound to a caller identity (see docs).
            presenter = getattr(request.state, "presenter", None)
            if presenter is not None and author_pubkey != presenter.pub_hex:
                return JSONResponse(
                    {"error": "append author must be the request presenter"},
                    status_code=403,
                )
            # Bound to ``document_key`` so a signed element cannot be replayed
            # under a different document key (see append_author_canonical_input).
            if not verify_append_author(
                document_key, sanitized_item, author_pubkey, author_signature
            ):
                return JSONResponse(
                    {"error": "invalid append author signature"}, status_code=403
                )
        author = (
            {AUTHOR_PUBKEY_FIELD: author_pubkey, AUTHOR_SIGNATURE_FIELD: author_signature}
            if author_pubkey is not None and author_signature is not None
            else None
        )

        # Optional client-supplied element timestamp (ms since epoch). When present
        # it must be a non-negative integer and strictly greater than the latest
        # stored element's ts (enforced in append_item); otherwise the server assigns one.
        provided_ts: int | None = None
        raw_ts = body.get(TS_FIELD)
        if raw_ts is not None:
            # bool is a subclass of int — reject it explicitly.
            if not isinstance(raw_ts, int) or isinstance(raw_ts, bool) or raw_ts < 0:
                return JSONResponse({"error": "ts must be a non-negative integer"}, status_code=400)
            if raw_ts > int(time.time_ns() // 1_000_000) + APPEND_MAX_FUTURE_TS_SKEW_MS:
                # Reject far-future timestamps so a writer can't poison the monotonic
                # counter and detach the log from wall-clock (breaking time checkpoints).
                return JSONResponse({"error": "ts is too far in the future"}, status_code=400)
            provided_ts = raw_ts

        if not append_cfg.persist:
            # queue-only path: no storage write. Resolve the element ts and return
            # its hash; the write event is emitted by the outer push handler.
            ts = provided_ts if provided_ts is not None else int(time.time_ns() // 1_000_000)
            item_hash = compute_hash(sanitized_item)
            return JSONResponse({"hash": item_hash, "timestamp": ts})

        # persist=true (default): append the element under the per-key write lock.
        # No hash/conflict check — an authorized append is always accepted (content-wise).
        # ``max_items``/``chunk_size`` (opt-in) cap the log / select segmented storage.
        outcome = await append_item(
            store, document_key, sanitized_item, append_field, provided_ts,
            max_items=append_cfg.max_items, chunk_size=append_cfg.chunk_size,
            author=author, context=context,
        )
        if isinstance(outcome, AppendLimitExceeded):
            # The cap is configuration, not data — safe to echo the limit.
            return JSONResponse({"error": outcome.error, "limit": outcome.limit}, status_code=409)
        if isinstance(outcome, AppendConflict):
            # Don't echo `latest` — it would leak the most-recent element's timestamp
            # to a write-only credential that has no read access to the log.
            return JSONResponse({"error": outcome.error}, status_code=409)
        return JSONResponse({"hash": outcome.hash, "timestamp": outcome.timestamp})

    return await handle_sync_push(
        document_key, store, body, identity,
        is_client_encrypted, False, context,
        getattr(request.state, "presenter", None),
    )


async def _run_binary_push(
    request: Request,
    col: CollectionConfig,
    document_key: str,
    identity: str | None,
    rate_limiter: RateLimiter | None,
    opts: SyncRouterOptions,
    context: StoreContext | None = None,
) -> Response:
    """Handle a binary push: validate MIME type, store raw bytes."""

    content_length = request.headers.get("content-length")
    limit_error = check_body_limit(content_length, col.max_body_bytes)
    if limit_error:
        return limit_error

    if rate_limiter:
        rate_error = rate_limiter.check(
            identity,
            request.headers.get("x-forwarded-for"),
            request.client.host if request.client else None,
        )
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
    await opts.store.put_bytes(document_key, body, content_type=media_type, context=context)

    return JSONResponse({"hash": content_hash})


async def _emit_write_event(
    opts: SyncRouterOptions,
    col: CollectionConfig,
    response: JSONResponse | Response,
    params: dict[str, str],
    body_data: dict[str, Any] | None = None,
    namespace_name: str | None = None,
) -> None:
    """Build a :class:`WriteEvent` from a successful push and dispatch it to
    every registered plugin's ``after_write`` hook.

    No-op when there are no plugins or the push did not return 200. Plugin
    failures are logged, never propagated.
    """
    if not opts.plugins or response.status_code != 200:
        return
    try:
        resp_body = json.loads(response.body)
    except Exception:
        logging.getLogger(__name__).error(
            "Failed to parse push response for write event on %s", col.name,
            exc_info=True,
        )
        return
    event = WriteEvent(
        collection=col.name,
        hash=resp_body.get("hash", ""),
        timestamp=resp_body.get("timestamp", 0),
        params=dict(params),
        body=body_data,
        namespace=namespace_name,
    )
    await dispatch_after_write(opts.plugins, event)


def _make_push_handler(
    col: CollectionConfig,
    rate_limiter: RateLimiter | None,
    opts: SyncRouterOptions,
    namespace_name: str | None = None,
) -> Callable:
    """Create a push handler with *col* and *rate_limiter* captured in a closure."""
    async def push_handler(request: Request) -> JSONResponse:
        params = request.path_params
        if not _validate_all_params(params):
            return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

        identity, effective_roles, error = await _check_auth(col, OP_WRITE, request, params, opts)
        if error:
            return error

        # Push-intercepting plugins (e.g. starfish-replica): reject read-only
        # collections, or respond on the route's behalf (e.g. proxy to a primary).
        if any(p.intercept_push is not None for p in (opts.plugins or [])):
            raw_body = (await request.body()).decode() if is_json_collection(col.allowed_mime_types) else ""
            decision = await dispatch_intercept_push(
                opts.plugins,
                PushHookContext(
                    collection=col.name,
                    params=dict(params),
                    raw_body=raw_body,
                    namespace=namespace_name,
                ),
            )
            if decision.action in ("reject", "respond"):
                # Push-through / rejected writes still pass local auth, so record
                # them in the audit log (they otherwise returned before the audit
                # call below, leaving proxied writes invisible). No write event is
                # emitted: the write lands on the primary, not the local store, so
                # the primary owns that change event.
                if opts.audit_logger is not None:
                    await opts.audit_logger.record(_AuditEntry(
                        timestamp=time.time() * 1000,
                        action="push",
                        collection=col.name,
                        identity=identity,
                        document_key=_resolve_document_key(col.storage_path, params),
                        success=200 <= decision.status < 300,
                        status_code=decision.status,
                        params=dict(params),
                    ))
                if decision.action == "reject":
                    return JSONResponse({"error": decision.error}, status_code=decision.status)
                return JSONResponse(decision.body, status_code=decision.status)

        document_key = _resolve_document_key(col.storage_path, params)
        push_ctx = StoreContext(
            collection=col.name,
            params=dict(params),
            identity=identity,
            roles=tuple(effective_roles),
            action=ACTION_PUSH,
            namespace=namespace_name,
        )

        if not is_json_collection(col.allowed_mime_types):
            response = await _run_binary_push(
                request, col, document_key, identity, rate_limiter, opts, push_ctx,
            )
            await _emit_write_event(opts, col, response, params, None, namespace_name)
            return response

        # Pre-extract the request `data` object so plugins' after_write hooks can
        # see the pushed body. Starlette caches the parsed JSON, so _run_push's
        # own parse below does not re-read the stream. A plugin decides whether
        # to use it.
        body_data: dict[str, Any] | None = None
        if any(p.after_write is not None for p in (opts.plugins or [])):
            try:
                raw = await request.json()  # Safe: Starlette.Request caches body in self._json after first read
                if isinstance(raw, dict) and isinstance(raw.get(DATA_FIELD), dict):
                    body_data = raw["data"]
                # Non-dict data → body_data stays None; a plugin that wanted the
                # body warns on its side.
            except Exception:
                # Parse failure → body_data stays None. _run_push re-parses and
                # rejects with 400, so the non-200 guard skips dispatch anyway.
                pass

        response = await _run_push(request, col, params, document_key, identity, effective_roles, rate_limiter, opts, push_ctx)
        await _emit_write_event(opts, col, response, params, body_data, namespace_name)
        # Emit audit entry for every push (success or conflict).
        if opts.audit_logger is not None:
            await opts.audit_logger.record(_AuditEntry(
                timestamp=time.time() * 1000,
                action="push",
                collection=col.name,
                identity=identity,
                document_key=document_key,
                success=response.status_code == 200,
                status_code=response.status_code,
                params=dict(params),
            ))
        return response

    return push_handler


def _add_collection_routes(
    router: APIRouter,
    col: CollectionConfig,
    opts: SyncRouterOptions,
    namespace_name: str | None = None,
) -> None:
    if not col.push_only:
        pull_path = _to_route_path(ACTION_PULL, col.storage_path)

        async def pull_handler(request: Request, col=col) -> JSONResponse:
            params = request.path_params
            if not _validate_all_params(params):
                return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

            identity, effective_roles, error = await _check_auth(col, OP_READ, request, params, opts)
            if error:
                return error

            pull_ctx = StoreContext(
                collection=col.name,
                params=dict(params),
                identity=identity,
                roles=tuple(effective_roles),
                action=ACTION_PULL,
                namespace=namespace_name,
            )

            # Pull-gating plugins (e.g. starfish-replica): reject write-only
            # collections, or sync from a primary before the local read.
            if any(p.before_pull is not None for p in (opts.plugins or [])):
                decision = await dispatch_before_pull(
                    opts.plugins,
                    PullHookContext(
                        collection=col.name,
                        params=dict(params),
                        namespace=namespace_name,
                    ),
                )
                if decision.action == "reject":
                    return JSONResponse({"error": decision.error}, status_code=decision.status)

            document_key = _resolve_document_key(col.storage_path, params)
            # Guard the resolved key before any store read. The JSON branch
            # re-checks inside handle_sync_pull, but the binary ``get_bytes``
            # branch below reads the store directly — without this, a
            # non-``{identity}`` param of ``..`` (which passes the per-segment
            # charset check) would traverse the composed key.
            if is_unsafe_document_key(document_key):
                return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

            # Binary collection: return raw bytes
            if not is_json_collection(col.allowed_mime_types):
                result = await opts.store.get_bytes(document_key, context=pull_ctx)
                if result is None:
                    return Response(status_code=404)
                raw_bytes, stored_content_type = result
                headers: dict[str, str] = {}
                binary_etag = f'"{hashlib.sha256(raw_bytes).hexdigest()}"'
                headers["ETag"] = binary_etag
                if_none_match = request.headers.get("if-none-match")
                if if_none_match == binary_etag:
                    return Response(status_code=304)
                if col.cache_duration_ms is not None:
                    max_age = col.cache_duration_ms // 1000
                    directive = (
                        f"max-age={max_age}"
                        if ROLE_PUBLIC in col.read_roles
                        else f"private, max-age={max_age}"
                    )
                    headers["Cache-Control"] = directive
                return Response(content=raw_bytes, media_type=stored_content_type, headers=headers)

            store = opts.store
            checkpoint_param = request.query_params.get(QUERY_CHECKPOINT)
            last_param = request.query_params.get("last")
            with_keyring = is_with_keyring_enabled(
                request.query_params.get("withKeyring")
            )
            # The sibling ``<key>/_keyring`` read must be authorized like any
            # other path: a cap that denies the keyring (e.g. scopes.writer)
            # must not read it via this shortcut. Drop the optimization when the
            # caller's cap scope does not cover the keyring key. ``None`` scope
            # (role-based auth, no path scope) leaves the optimization enabled.
            if with_keyring:
                cap_scope_paths = getattr(request.state, "cap_scope_paths", None)
                if cap_scope_paths is not None and not match_scope_path(
                    f"{document_key}/_keyring", cap_scope_paths
                ):
                    with_keyring = False
            is_client_encrypted = col.encryption == ENCRYPTION_DELEGATED
            is_public = ROLE_PUBLIC in col.read_roles

            # AppendOnly persist=true uses custom per-item checkpoint filtering
            if col.append_only is not None and col.append_only.persist:
                response = await handle_append_only_pull(
                    document_key, store, checkpoint_param,
                    col.append_only.field,
                    col.cache_duration_ms,
                    is_public=is_public,
                    last_param=last_param,
                    context=pull_ctx,
                )
            else:
                response = await handle_sync_pull(
                    document_key, store, checkpoint_param,
                    bool(col.force_full_fetch), is_client_encrypted,
                    col.cache_duration_ms,
                    is_public=is_public,
                    context=pull_ctx,
                    with_keyring=with_keyring,
                )

            # TTL: if the document has expired, return empty data.
            # Python pull() returns the current time, not the stored timestamp,
            # so read the stored doc-level write-time (`ts`) directly to check expiry.
            # Use the resolved encrypted `store` (not opts.store) so encrypted
            # collections are decrypted before timestamp extraction.
            if col.ttl_ms is not None and response.status_code == 200:
                raw_doc = await store.get_string(document_key, context=pull_ctx)
                if raw_doc:
                    stored = json.loads(raw_doc)
                    doc_timestamp = stored.get("ts") or 0
                    if _is_expired(doc_timestamp, col.ttl_ms):
                        resp_body = json.loads(response.body)
                        resp_body["data"] = {}
                        resp_body["hash"] = ""  # zero hash so client can't clobber with stale baseHash
                        response = JSONResponse(resp_body, status_code=200)
                        if col.cache_duration_ms is not None:
                            max_age = col.cache_duration_ms // 1000
                            directive = (
                                f"max-age={max_age}"
                                if ROLE_PUBLIC in col.read_roles
                                else f"private, max-age={max_age}"
                            )
                            response.headers["Cache-Control"] = directive

            # Field-level read permission filtering
            if col.field_permissions and response.status_code == 200:
                resp_body = json.loads(response.body)
                if isinstance(resp_body.get(DATA_FIELD), dict):
                    data = dict(resp_body["data"])
                    for field_name, fp in col.field_permissions.items():
                        if fp.read_roles and field_name in data:
                            # ROLE_PUBLIC fields are visible to everyone, including
                            # authenticated users (matches TypeScript behaviour)
                            if not any(
                                r in effective_roles or r == ROLE_PUBLIC
                                for r in fp.read_roles
                            ):
                                del data[field_name]
                    resp_body["data"] = data
                    # Field filtering changes the body VIEW, not the document version,
                    # so the hash-derived ETag (and Cache-Control) still apply — carry
                    # them across the rebuild instead of dropping them, otherwise
                    # conditional 304 caching silently breaks for field-perm collections
                    # (TS keeps the ETag by filtering `data` in place).
                    preserved = {
                        k: v
                        for k, v in response.headers.items()
                        if k.lower() in ("etag", "cache-control")
                    }
                    response = JSONResponse(resp_body, status_code=200)
                    for k, v in preserved.items():
                        response.headers[k] = v

            # ETag conditional request support
            etag = response.headers.get("ETag")
            if etag:
                if_none_match = request.headers.get("if-none-match")
                if if_none_match == etag:
                    return Response(status_code=304)

            return response

        router.add_api_route(pull_path, pull_handler, methods=["GET"])

    if not col.pull_only:
        push_path = _to_route_path(ACTION_PUSH, col.storage_path)
        rate_limiter = _build_rate_limiter(col.rate_limit, opts)
        router.add_api_route(
            push_path, _make_push_handler(col, rate_limiter, opts, namespace_name), methods=["POST"],
        )

    if col.listable:
        list_path = _to_list_route_path(col.storage_path)

        def _make_list_handler(col: CollectionConfig, ns: str | None) -> Callable:
            async def list_handler(request: Request) -> JSONResponse:
                # The list route has one fewer path param than storagePath.
                # Resolve only the prefix portion.
                segments = col.storage_path.split("/")
                prefix_template = "/".join(segments[:-1])
                params = dict(request.path_params)

                if not _validate_all_params(params):
                    return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

                list_identity, list_roles, error = await _check_auth(col, OP_READ, request, params, opts)
                if error:
                    return error

                list_ctx = StoreContext(
                    collection=col.name,
                    params=params,
                    identity=list_identity,
                    roles=tuple(list_roles),
                    action=ACTION_LIST,
                    namespace=ns,
                )

                prefix = _to_list_prefix(col.storage_path, params)

                # Parse ?limit
                limit = _LIST_DEFAULT_LIMIT
                limit_param = request.query_params.get("limit")
                if limit_param is not None:
                    try:
                        limit = int(limit_param)
                        if limit <= 0 or str(limit) != limit_param:
                            raise ValueError
                    except ValueError:
                        return JSONResponse({"error": "Invalid limit parameter"}, status_code=400)
                    limit = min(limit, _LIST_MAX_LIMIT)

                # Parse ?after for cursor pagination
                start_after: str | None = None
                after_param = request.query_params.get("after")
                if after_param is not None:
                    start_after = prefix + after_param

                # Fetch one extra to detect hasMore
                keys = await opts.store.list_keys(prefix, start_after=start_after, limit=limit + 1, context=list_ctx)
                has_more = len(keys) > limit
                page = keys[:limit] if has_more else keys

                items = [k[len(prefix):] for k in page]
                return JSONResponse({"items": items, "hasMore": has_more})

            return list_handler

        router.add_api_route(list_path, _make_list_handler(col, namespace_name), methods=["GET"])


def _add_bundled_routes(
    router: APIRouter,
    bundle_name: str,
    collections: list[CollectionConfig],
    opts: SyncRouterOptions,
    namespace_name: str | None = None,
) -> None:
    storage_path = collections[0].storage_path

    pull_path = _to_route_path(ACTION_PULL, storage_path)
    # A bundle member is "public" when its own read_roles allow ROLE_PUBLIC.
    # Non-public members (including rootOnly ones) are each authorized against
    # the caller's resolved roles; a public member never relaxes a private
    # sibling.
    has_non_public = any(
        c.root_only or ROLE_PUBLIC not in c.read_roles for c in collections
    )

    async def bundle_pull_handler(request: Request) -> JSONResponse:
        params = request.path_params
        if not _validate_all_params(params):
            return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

        # Resolve the caller's effective roles ONCE (the resolver consumes the
        # request nonce, so it must not run per-collection). Skipped entirely
        # when every member is public, preserving anonymous access to all-public
        # bundles.
        identity: str | None = None
        effective_roles: frozenset[str] = frozenset()
        if has_non_public:
            identity, effective_roles, error = await _resolve_effective_roles(
                request, params, opts, storage_path
            )
            if error:
                return error

        base_key = _resolve_document_key(storage_path, params)
        # Guard the resolved key: the per-member loop below reads the store
        # directly (it does not go through handle_sync_pull), so a ``..`` in a
        # non-``{identity}`` param would otherwise traverse the composed key.
        if is_unsafe_document_key(base_key):
            return JSONResponse({"error": "Invalid path parameter"}, status_code=400)
        store = opts.store

        # Bundles contain only regular collections, which always return the full
        # document — ``?checkpoint=`` is no longer honored (appendOnly-only feature).
        result: dict[str, Any] = {}
        latest_timestamp = 0

        for col in collections:
            # Per-collection authorization via the shared decision so a bundle
            # pull enforces exactly what the standalone pull does (read_roles,
            # public, and rootOnly). Denied members are omitted so a bundle never
            # leaks a collection the caller can't read.
            if not _is_access_allowed(col, OP_READ, effective_roles):
                continue

            document_key = f"{base_key}/{col.name}"
            bundle_pull_ctx = StoreContext(
                collection=col.name,
                params=dict(params),
                identity=identity,
                roles=tuple(effective_roles),
                action=ACTION_PULL,
                namespace=namespace_name,
            )
            pull_result = await pull(store, document_key, bundle_pull_ctx)
            # Strip fields the caller cannot read (parity with the standalone path).
            _apply_field_read_filter(pull_result.data, col.field_permissions, effective_roles)
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

        def _make_bundle_push(col: CollectionConfig, rl: RateLimiter | None, ns: str | None) -> Callable:
            async def bundle_push_handler(request: Request) -> JSONResponse:
                params = request.path_params
                if not _validate_all_params(params):
                    return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

                identity, effective_roles, error = await _check_auth(col, OP_WRITE, request, params, opts)
                if error:
                    return error

                document_key = f"{_resolve_document_key(storage_path, params)}/{col.name}"
                bundle_push_ctx = StoreContext(
                    collection=col.name,
                    params=dict(params),
                    identity=identity,
                    roles=tuple(effective_roles),
                    action=ACTION_PUSH,
                    namespace=ns,
                )

                # See the JSON-push handler: pre-extract `data` for plugins'
                # after_write hooks; Starlette caches the parse so _run_push below
                # does not re-read.
                bundle_body_data: dict[str, Any] | None = None
                if any(p.after_write is not None for p in (opts.plugins or [])):
                    try:
                        raw = await request.json()  # Safe: Starlette.Request caches body in self._json after first read
                        if isinstance(raw, dict) and isinstance(raw.get(DATA_FIELD), dict):
                            bundle_body_data = raw["data"]
                    except Exception:
                        # Parse failure → bundle_body_data stays None; non-200 guard
                        # skips dispatch anyway.
                        pass

                response = await _run_push(request, col, params, document_key, identity, effective_roles, rl, opts, bundle_push_ctx)
                await _emit_write_event(opts, col, response, params, bundle_body_data, ns)
                return response

            return bundle_push_handler

        router.add_api_route(push_path, _make_bundle_push(col, rate_limiter, namespace_name), methods=["POST"])


def _register_collections_on_router(
    router: APIRouter,
    collections: list[CollectionConfig],
    opts: SyncRouterOptions,
    namespace_name: str | None = None,
) -> None:
    """Register standalone and bundled collection routes on *router*."""
    bundles: dict[str, list[CollectionConfig]] = {}
    standalone: list[CollectionConfig] = []

    for col in collections:
        if col.bundle:
            bundles.setdefault(col.bundle, []).append(col)
        else:
            standalone.append(col)

    for col in standalone:
        _add_collection_routes(router, col, opts, namespace_name)

    for bundle_name, bundle_collections in bundles.items():
        _add_bundled_routes(router, bundle_name, bundle_collections, opts, namespace_name)


def _make_batch_pull_handler(
    collections_by_name: dict[str, CollectionConfig],
    opts: SyncRouterOptions,
    namespace_name: str | None = None,
) -> Callable:
    """Create a ``/batch/pull`` handler scoped to *collections_by_name*."""
    async def batch_pull_handler(request: Request) -> JSONResponse:
        # 400 only when `collections` itself is absent/empty; once present, empty
        # CSV slots (`,a,,`) are dropped rather than turned into spurious `""` →
        # "Collection not found" entries. An all-empty `,,` therefore resolves to
        # no names and returns `{ collections: {} }`. (Parity with the TS handler.)
        raw_param = request.query_params.get("collections")
        if not raw_param:
            return JSONResponse(
                {"error": "Missing required query parameter: collections"},
                status_code=400,
            )

        # De-duplicate (preserving order): the result map is keyed by name, so a
        # repeated name only ever overwrote itself — deduping makes that explicit
        # and stops `?collections=a,a,a,…` from driving repeated reads of one doc.
        names = list(dict.fromkeys(n.strip() for n in raw_param.split(",") if n.strip()))

        # Bound the per-request work: one signed request fans out to a store read +
        # enricher + scope check per collection, and the rate limiter caps requests,
        # not work-per-request. Reject an oversized batch (distinct names) up front.
        if len(names) > opts.max_collections_per_batch:
            return JSONResponse({"error": "Too many collections"}, status_code=400)

        # Optional `params`: URL-encoded JSON mapping collection name → an ARRAY of
        # path-param sets, one per document to read from that collection, e.g.
        # `{"profile":[{"identity":"a"},{"identity":"b"}]}` reads two profiles.
        # `{identity}` is auto-filled from the caller below, so a set may omit it. A
        # malformed blob is a client framing error → whole-request 400, rather than
        # silently dropping params for every collection.
        params_by_collection: dict[str, list[dict[str, Any]]] = {}
        raw_params = request.query_params.get("params")
        if raw_params:
            try:
                parsed = json.loads(raw_params)
            except (ValueError, TypeError, RecursionError):
                # RecursionError guards a pathologically deep blob (json's C
                # decoder can raise it rather than a ValueError) — still a client
                # framing error, not a 500.
                return JSONResponse({"error": "Invalid params parameter"}, status_code=400)
            # Each value is an array of param-sets; every element must be a dict. An
            # array of arrays/scalars (or a bare object) is a framing error → 400.
            if not isinstance(parsed, dict) or any(
                not isinstance(v, list) or any(not isinstance(e, dict) for e in v)
                for v in parsed.values()
            ):
                return JSONResponse({"error": "Invalid params parameter"}, status_code=400)
            params_by_collection = parsed

        # Bound the TOTAL reads (Σ param-sets across collections), not just the count
        # of distinct names: with array params one name can fan in many documents, so
        # the distinct-name cap above is necessary but no longer sufficient. A name
        # absent from `params` reads one auto-filled doc (counts as 1).
        total_reads = sum(
            len(params_by_collection[name]) if name in params_by_collection else 1
            for name in names
        )
        if total_reads > opts.max_collections_per_batch:
            return JSONResponse({"error": "Too many collections"}, status_code=400)

        # Resolve the caller's base auth ONCE — the resolver consumes the request
        # nonce, so it must not run per-collection. Per-collection `self`/enricher
        # roles are folded below from this single resolve. A resolver error is NOT
        # fatal to the batch: it degrades to anonymous so public collections still
        # resolve and private ones return per-collection "Forbidden", matching the
        # pre-params handler (which authorized each collection independently and
        # mapped any auth error to a per-collection "Forbidden").
        auth, base_identity, base_roles, auth_error = await _resolve_base_auth(request, opts)
        identity = base_identity if auth is not None else None
        # Cap-scoped auth carries `scope.paths`; the resolver skips its URL
        # path-scope check for /batch/pull (the URL names no storage path), so we
        # re-check each RESOLVED key against this scope below. None (role-based auth
        # or an unrestricted device cap) imposes no restriction.
        scope_paths = getattr(request.state, "cap_scope_paths", None)

        # Audit: mirror the standalone pull's points — a per-collection record on
        # each auth denial (403/500) and successful read. Awaited like the standalone
        # path. (The 400-class missing/invalid-param branches are NOT audited,
        # matching the standalone path which only audits via _check_auth's denials.)
        async def _record_audit(
            collection: str, document_key: str, success: bool,
            status_code: int, audit_params: dict[str, str],
        ) -> None:
            if opts.audit_logger is None:
                return
            try:
                await opts.audit_logger.record(_AuditEntry(
                    timestamp=time.time() * 1000,
                    action="pull",
                    collection=collection,
                    identity=identity,
                    document_key=document_key,
                    success=success,
                    status_code=status_code,
                    # Snapshot: the entry may be persisted/async-processed by the
                    # logger, so copy rather than alias the live params dict.
                    params=dict(audit_params),
                ))
            except Exception:
                # Audit is best-effort here: the success record runs inside the
                # per-collection read try/except, so a throwing logger must NOT
                # relabel a successful read as "Internal error" (nor 500 the batch
                # from the request-level degrade record). Log and continue. This
                # intentionally diverges from the standalone path, which lets an
                # audit throw propagate — tolerable for a single-document request,
                # not for a multi-collection one.
                logging.getLogger(__name__).error(
                    "Batch pull audit record failed", exc_info=True
                )

        # The resolver hard-failed but we degrade to anonymous (so public collections
        # still resolve) — record it so a revoked/expired/bad-sig cap is not an audit
        # blind spot. ``collection=""`` marks it a request-level event.
        if auth_error is not None:
            await _record_audit("", "", False, auth_error.status_code, {})

        store = opts.store

        async def _resolve_entry(
            col: CollectionConfig, supplied: dict[str, Any]
        ) -> dict[str, Any]:
            # Resolve ONE document of `col` for a single supplied param-set,
            # returning its result entry (`{data,hash,timestamp}` or `{error}`).
            # Factored out of the loop so a collection's array of param-sets each
            # runs the identical params → auth-fold → access → key → scope → pull →
            # field-filter pipeline.
            #
            # Effective params built from ONLY the template's params (parity with
            # the standalone path): caller-supplied keys outside the template are
            # ignored, so they can't reach the store context, plugins, or audit
            # log. Values must be str/number. `{identity}` auto-fills from the
            # authenticated caller when the path needs it and none was supplied; an
            # explicitly supplied identity is kept as-is, so a forged identity is
            # denied below via the missing-`self` path rather than silently rewritten.
            required_params = re.findall(r"\{(\w+)\}", col.storage_path)
            effective_params: dict[str, str] = {}
            for p in required_params:
                v = supplied.get(p)
                if isinstance(v, str):
                    effective_params[p] = v
                elif isinstance(v, (int, float)) and not isinstance(v, bool):
                    effective_params[p] = str(v)
            if (
                IDENTITY_KEY in required_params
                and IDENTITY_KEY not in effective_params
                and identity
            ):
                # Truthy `identity` excludes both None and the anonymous "" — an
                # anonymous caller has no identity to bind, so `{identity}` falls
                # through to the missing-required-param guard below (no degenerate
                # empty key).
                effective_params[IDENTITY_KEY] = identity

            # A required param with no supplied/auto-filled value cannot be addressed.
            if any(p not in effective_params for p in required_params):
                return {"error": "Missing required path parameter"}
            # Charset-validate each value (blocks `/` and other unsafe chars).
            if not _validate_all_params(effective_params):
                return {"error": "Invalid path parameter"}

            # Fold per-collection `self` + enricher roles from the single base
            # resolve. Anonymous (or degraded) callers carry no roles, so only
            # public-read collections pass _is_access_allowed below.
            if auth is not None:
                effective_roles, fold_error = await _fold_collection_roles(
                    auth, base_roles, effective_params, col.storage_path, opts
                )
                if fold_error is not None:
                    await _record_audit(col.name, "", False, 500, effective_params)
                    return {"error": "Authorization error"}
            else:
                effective_roles = frozenset()

            if not _is_access_allowed(col, OP_READ, effective_roles):
                await _record_audit(col.name, "", False, 403, effective_params)
                return {"error": "Forbidden"}

            try:
                key = _resolve_document_key(col.storage_path, effective_params)
                # Guard the resolved key: validate_path_segment admits `..`, so a
                # supplied param could compose a traversal key. Reject before
                # touching the store (parity with the standalone and bundle paths).
                if is_unsafe_document_key(key):
                    return {"error": "Invalid path parameter"}
                # Cap path-scope: the resolver couldn't bind /batch/pull to a
                # storage path, so enforce the cap's scope against the RESOLVED key
                # here — a cap may only batch-read keys its scope covers (e.g. its
                # own room, not a sibling). This stops batch from side-stepping
                # per-path scope.
                if not match_scope_path(key, scope_paths):
                    await _record_audit(col.name, key, False, 403, effective_params)
                    return {"error": "Forbidden"}
                batch_ctx = StoreContext(
                    collection=col.name,
                    params=effective_params,
                    identity=identity,
                    roles=tuple(effective_roles),
                    action=ACTION_PULL,
                    namespace=namespace_name,
                )
                pull_result = await pull(store, key, batch_ctx)
                data = pull_result.data

                # TTL check: pull() returns now as its timestamp, so read the stored
                # doc-level write-time (`ts`) to expire stale documents.
                if col.ttl_ms is not None:
                    raw_doc = await opts.store.get_string(key, context=batch_ctx)
                    if raw_doc:
                        stored = json.loads(raw_doc)
                        doc_timestamp = stored.get("ts") or 0
                        if _is_expired(doc_timestamp, col.ttl_ms):
                            data = {}

                # Strip fields the caller cannot read (parity with the standalone path).
                _apply_field_read_filter(data, col.field_permissions, effective_roles)

                await _record_audit(col.name, key, True, 200, effective_params)
                return {
                    "data": data,
                    "hash": pull_result.hash,
                    "timestamp": pull_result.timestamp,
                }
            except Exception as exc:
                logging.getLogger(__name__).error(
                    "Batch pull failed for collection %r: %s", col.name, exc, exc_info=True,
                )
                return {"error": "Internal error"}

        results: dict[str, Any] = {}
        for name in names:
            # A name absent from `params` reads one auto-filled doc (`[{}]`);
            # present means an array of param-sets, possibly empty (→ no reads, []).
            param_sets = params_by_collection.get(name)
            if param_sets is None:
                param_sets = [{}]
            col = collections_by_name.get(name)
            if col is None:
                # One error entry PER requested set so the array stays index-aligned
                # with the caller's input (batch_pull_many indexes by position).
                results[name] = [{"error": "Collection not found"} for _ in param_sets]
                continue
            results[name] = [await _resolve_entry(col, supplied) for supplied in param_sets]

        return JSONResponse({"collections": results})

    return batch_pull_handler


def _mount_namespace(
    router: APIRouter,
    ns_name: str,
    ns_config: NamespaceConfig,
    opts: SyncRouterOptions,
) -> None:
    """Create a sub-router for *ns_name* and mount it on *router*."""
    ns_router = APIRouter()
    _register_collections_on_router(ns_router, ns_config.collections, opts, ns_name)

    collections_by_name = {col.name: col for col in ns_config.collections if not col.bundle}
    ns_router.add_api_route(
        "/batch/pull",
        _make_batch_pull_handler(collections_by_name, opts, ns_name),
        methods=["GET"],
    )

    router.include_router(ns_router, prefix=f"/{ns_name}")


def create_sync_router(opts: SyncRouterOptions) -> APIRouter:
    """Create a FastAPI APIRouter with sync pull/push routes.

    CORS is not configured here — add CORSMiddleware to your FastAPI app if needed.
    Register replica/queuing plugins via ``GracefulShutdownOptions(plugins=[...])``
    so their ``shutdown`` hooks (e.g. ``starfish-replica`` stopping its sync timers) run.
    """
    router = APIRouter()
    config = opts.config

    # `appendOnly.persist=False` computes a hash and emits a write event without
    # writing to storage — it only does something useful when a plugin consumes
    # the event (e.g. ``starfish-queuing``). Warn if no after_write hook is wired.
    if not any(p.after_write is not None for p in (opts.plugins or [])):
        all_cols = list(config.collections)
        for ns in (config.namespaces or {}).values():
            all_cols.extend(ns.collections)
        queue_only = [
            c for c in all_cols
            if c.append_only is not None and c.append_only.persist is False
        ]
        if queue_only:
            logging.getLogger(__name__).warning(
                "appendOnly.persist=False on collection(s) %s but no plugin with an "
                "after_write hook is registered; pushes will be neither stored nor "
                "published.",
                ", ".join(repr(c.name) for c in queue_only),
            )

    @router.get("/health")
    async def health() -> dict:
        return {"ok": True, "ts": int(time.time() * 1000)}

    if opts.config_endpoint is not None:
        cfg_opts = opts.config_endpoint

        @router.get("/config")
        async def get_config(request: Request) -> ConfigResponse:
            caller_roles: list[str] = []
            if cfg_opts.auth == "role-filtered":
                try:
                    auth_result = await opts.role_resolver(request)
                    caller_roles = auth_result.roles
                except Exception as exc:
                    logging.getLogger(__name__).error(
                        "/config: role_resolver raised: %s", exc, exc_info=True
                    )
                    # return empty collections rather than 5xx

            def is_visible(col: CollectionConfig) -> bool:
                if cfg_opts.auth == "public":
                    return True
                return bool(
                    set(col.read_roles) & set(caller_roles)
                    or set(col.write_roles) & set(caller_roles)
                )

            ns_info: dict[str, _NamespaceClientInfo] | None = None
            if config.namespaces:
                ns_info = {
                    ns_name: _NamespaceClientInfo(
                        collections=[_to_collection_client_info(c) for c in ns_cfg.collections if is_visible(c)]
                    )
                    for ns_name, ns_cfg in config.namespaces.items()
                }

            resp = ConfigResponse(
                collections=[_to_collection_client_info(c) for c in config.collections if is_visible(c)],
                namespaces=ns_info,
            )
            return JSONResponse(content=resp.model_dump(exclude_none=True))

    _register_collections_on_router(router, config.collections, opts)

    root_collections_by_name = {col.name: col for col in config.collections if not col.bundle}
    router.add_api_route(
        "/batch/pull",
        _make_batch_pull_handler(root_collections_by_name, opts),
        methods=["GET"],
    )

    if config.namespaces:
        for ns_name, ns_config in config.namespaces.items():
            _mount_namespace(router, ns_name, ns_config, opts)

    return router
