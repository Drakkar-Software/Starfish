"""Starfish sync protocol server."""

from starfish_server.errors import StartupError, AuthError, ConflictError, NotFoundError
from starfish_server.constants import (
    ROLE_PUBLIC,
    ROLE_SELF,
    OP_READ,
    OP_WRITE,
    ENCRYPTION_NONE,
    ENCRYPTION_IDENTITY,
    ENCRYPTION_SERVER,
    ENCRYPTION_DELEGATED,
    ACTION_PULL,
    ACTION_PUSH,
    IDENTITY_PARAM,
    IDENTITY_KEY,
    QUERY_CHECKPOINT,
    HKDF_INFO_DEFAULT,
    HKDF_INFO_IDENTITY,
    HKDF_INFO_SERVER,
    DEFAULT_CONFIG_KEY,
    ERROR_HASH_MISMATCH,
    CONTENT_TYPE_JSON,
)
from starfish_protocol.hash import stable_stringify, compute_hash
from starfish_protocol.merge import deep_merge
from starfish_server.protocol.types import StoredDocument, PullResult, PushResult, Timestamps
from starfish_server.protocol.timestamps import compute_timestamps, filter_by_checkpoint
from starfish_server.protocol.pull import pull
from starfish_server.protocol.push import push
from starfish_server.encryption.encrypted_store import EncryptedObjectStore
from starfish_server.config.schema import (
    SyncConfig,
    CollectionConfig,
    CollectionRateLimitConfig,
    FieldPermission,
    NamespaceConfig,
    QueueConfig,
    RateLimitConfig,
    EncryptionMode,
    RemoteConfig,
    WriteMode,
    SyncTrigger,
)
from starfish_server.config.validate import validate_config
from starfish_server.config.loader import load_config, save_config, parse_config_json, load_config_file
from starfish_server.replica import ReplicaManager
from starfish_server.queue import AbstractQueue, MemoryQueue, CustomQueue
from starfish_server.storage.base import AbstractObjectStore
from starfish_server.storage.filesystem import FilesystemObjectStore, FilesystemStorageOptions
from starfish_server.storage.memory import MemoryObjectStore, CustomObjectStore
from starfish_server.lifecycle import GracefulShutdown, GracefulShutdownOptions
from starfish_server.router.middleware import (
    CorsConfig,
    SecurityHeadersConfig,
    SecurityHeadersMiddleware,
    RequestTimeoutMiddleware,
    configure_middleware,
)
from starfish_server.logger import ServerLogger, ConsoleLogger, JsonLogger, NoopLogger, LogEntry
from starfish_server.audit import AuditLogger, AuditEntry, ConsoleAuditLogger, CallbackAuditLogger, NoopAuditLogger
from starfish_server.ttl import is_expired
from starfish_server.openapi import generate_openapi_spec

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
    "ENCRYPTION_IDENTITY",
    "ENCRYPTION_SERVER",
    "ENCRYPTION_DELEGATED",
    "ACTION_PULL",
    "ACTION_PUSH",
    "IDENTITY_PARAM",
    "IDENTITY_KEY",
    "QUERY_CHECKPOINT",
    "HKDF_INFO_DEFAULT",
    "HKDF_INFO_IDENTITY",
    "HKDF_INFO_SERVER",
    "DEFAULT_CONFIG_KEY",
    "ERROR_HASH_MISMATCH",
    "CONTENT_TYPE_JSON",
    "stable_stringify",
    "compute_hash",
    "StoredDocument",
    "PullResult",
    "PushResult",
    "Timestamps",
    "compute_timestamps",
    "filter_by_checkpoint",
    "pull",
    "push",
    "EncryptedObjectStore",
    "SyncConfig",
    "CollectionConfig",
    "CollectionRateLimitConfig",
    "FieldPermission",
    "NamespaceConfig",
    "QueueConfig",
    "RateLimitConfig",
    "EncryptionMode",
    "RemoteConfig",
    "WriteMode",
    "SyncTrigger",
    "validate_config",
    "load_config",
    "save_config",
    "parse_config_json",
    "load_config_file",
    "ReplicaManager",
    "AbstractQueue",
    "MemoryQueue",
    "CustomQueue",
    "AbstractObjectStore",
    "FilesystemObjectStore",
    "FilesystemStorageOptions",
    "MemoryObjectStore",
    "CustomObjectStore",
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
    "AuditLogger",
    "AuditEntry",
    "ConsoleAuditLogger",
    "CallbackAuditLogger",
    "NoopAuditLogger",
    "is_expired",
    "generate_openapi_spec",
]
