"""Starfish sync protocol server."""

from starfish_server.errors import StartupError, AuthError, ConflictError, NotFoundError
from starfish_server.constants import (
    ROLE_PUBLIC,
    ROLE_SELF,
    OP_READ,
    OP_WRITE,
    ENCRYPTION_NONE,
    ENCRYPTION_DELEGATED,
    ACTION_PULL,
    ACTION_PUSH,
    ACTION_LIST,
    IDENTITY_PARAM,
    IDENTITY_KEY,
    QUERY_CHECKPOINT,
    HKDF_INFO_DEFAULT,
    DEFAULT_CONFIG_KEY,
    ERROR_HASH_MISMATCH,
    CONTENT_TYPE_JSON,
)
from starfish_protocol.hash import stable_stringify, compute_hash
from starfish_protocol.merge import deep_merge
from starfish_server.protocol.types import StoredDocument, AppendElement, PullResult, PushResult
from starfish_server.protocol.pull import pull
from starfish_server.protocol.push import push, append_item
from starfish_server.config.schema import (
    SyncConfig,
    CollectionConfig,
    CollectionRateLimitConfig,
    RateLimitRule,
    RateLimitDimension,
    FieldPermission,
    IdentityRestriction,
    NamespaceConfig,
    RateLimitConfig,
    EncryptionMode,
    ConfigEndpointOptions,
)
from starfish_server.router.route_builder import CollectionClientInfo, ConfigResponse
from starfish_server.config.validate import collect_config_warnings, validate_config
from starfish_server.config.loader import load_config, save_config, parse_config_json, load_config_file
from starfish_server.storage.base import AbstractObjectStore, StoreContext
from starfish_server.storage.filesystem import FilesystemObjectStore, FilesystemStorageOptions
from starfish_server.storage.memory import MemoryObjectStore, CustomObjectStore
from starfish_server.storage.kv_adapter import KVAdapter, create_in_memory_kv_adapter
from starfish_server.storage.k2v_adapter import K2VTransport, K2VReadResult, create_k2v_adapter
from starfish_server.lifecycle import GracefulShutdown, GracefulShutdownOptions
from starfish_server.router.middleware import (
    CorsConfig,
    SecurityHeadersConfig,
    SecurityHeadersMiddleware,
    RequestTimeoutMiddleware,
    configure_middleware,
)
from starfish_server.logger import ServerLogger, ConsoleLogger, JsonLogger, NoopLogger, LogEntry
from starfish_server.ttl import is_expired
from starfish_server.openapi import generate_openapi_spec
from starfish_server.enrichers.compose import compose_enrichers
from starfish_server.auth.nonce_cache import (
    NonceCache,
    create_in_memory_nonce_cache,
    create_kv_nonce_cache,
)
from starfish_server.auth.revocation_store import (
    REVOCATION_RETAIN_SKEW_SEC,
    RevocationEntry,
    RevocationList,
    RevocationStore,
    RevokedSubject,
    create_in_memory_revocation_store,
    revocation_retain_until_sec,
)
from starfish_server.router.cap_resolver import (
    CapAuthError,
    authenticate_meta_request,
    create_cap_cert_role_resolver,
)
from starfish_server.enrichers.identity import make_identity_role_enricher
from starfish_server.events_proxy import (
    DEFAULT_SAFE_ID,
    create_events_proxy_router,
)
from starfish_server.plugins import (
    CapCertValidator,
    ServerPlugin,
    WriteEvent,
    compose_plugin_validators,
    default_server_plugin,
    dispatch_after_write,
    dispatch_authorize,
    has_authorize_hook,
)
from starfish_protocol.plugins import (
    AuthorizeContext,
    AuthorizeResult,
)

__all__ = [
    "StartupError",
    "AuthError",
    "ConflictError",
    "NotFoundError",
    "ROLE_PUBLIC",
    "ROLE_SELF",
    "OP_READ",
    "OP_WRITE",
    "ENCRYPTION_NONE",
    "ENCRYPTION_DELEGATED",
    "ACTION_PULL",
    "ACTION_PUSH",
    "ACTION_LIST",
    "IDENTITY_PARAM",
    "IDENTITY_KEY",
    "QUERY_CHECKPOINT",
    "HKDF_INFO_DEFAULT",
    "DEFAULT_CONFIG_KEY",
    "ERROR_HASH_MISMATCH",
    "CONTENT_TYPE_JSON",
    "stable_stringify",
    "compute_hash",
    "StoredDocument",
    "AppendElement",
    "PullResult",
    "PushResult",
    "pull",
    "push",
    "append_item",
    "SyncConfig",
    "CollectionConfig",
    "CollectionRateLimitConfig",
    "RateLimitRule",
    "RateLimitDimension",
    "FieldPermission",
    "IdentityRestriction",
    "NamespaceConfig",
    "RateLimitConfig",
    "EncryptionMode",
    "ConfigEndpointOptions",
    "CollectionClientInfo",
    "ConfigResponse",
    "validate_config",
    "collect_config_warnings",
    "load_config",
    "save_config",
    "parse_config_json",
    "load_config_file",
    "AbstractObjectStore",
    "StoreContext",
    "FilesystemObjectStore",
    "FilesystemStorageOptions",
    "MemoryObjectStore",
    "CustomObjectStore",
    "KVAdapter",
    "create_in_memory_kv_adapter",
    "K2VTransport",
    "K2VReadResult",
    "create_k2v_adapter",
    "GracefulShutdown",
    "GracefulShutdownOptions",
    "CorsConfig",
    "SecurityHeadersConfig",
    "SecurityHeadersMiddleware",
    "RequestTimeoutMiddleware",
    "configure_middleware",
    "ServerLogger",
    "ConsoleLogger",
    "JsonLogger",
    "NoopLogger",
    "LogEntry",
    "is_expired",
    "generate_openapi_spec",
    "compose_enrichers",
    "make_identity_role_enricher",
    "DEFAULT_SAFE_ID",
    "create_events_proxy_router",
    "NonceCache",
    "create_in_memory_nonce_cache",
    "create_kv_nonce_cache",
    "RevocationEntry",
    "RevocationList",
    "RevokedSubject",
    "RevocationStore",
    "REVOCATION_RETAIN_SKEW_SEC",
    "create_in_memory_revocation_store",
    "revocation_retain_until_sec",
    "CapAuthError",
    "authenticate_meta_request",
    "create_cap_cert_role_resolver",
    "CapCertValidator",
    "ServerPlugin",
    "WriteEvent",
    "compose_plugin_validators",
    "default_server_plugin",
    "dispatch_after_write",
    "dispatch_authorize",
    "has_authorize_hook",
    "AuthorizeContext",
    "AuthorizeResult",
]
