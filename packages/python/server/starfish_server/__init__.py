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
    RateLimitConfig,
    EncryptionMode,
    RemoteConfig,
    WriteMode,
    SyncTrigger,
)
from starfish_server.config.validate import validate_config
from starfish_server.config.loader import load_config, save_config, parse_config_json, load_config_file
from starfish_server.replica import (
    ReplicaManager,
    NotificationPublisher,
    Subscription,
    SubscriptionStore,
    create_replica_router,
)
from starfish_server.storage.base import AbstractObjectStore
from starfish_server.storage.filesystem import FilesystemObjectStore, FilesystemStorageOptions
from starfish_server.storage.memory import MemoryObjectStore, CustomObjectStore

try:
    from starfish_server.storage.sui import SuiObjectStore, SuiStorageOptions
except ImportError:  # pysui not installed — SUI adapter unavailable
    pass

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
    "NotificationPublisher",
    "Subscription",
    "SubscriptionStore",
    "create_replica_router",
    "AbstractObjectStore",
    "FilesystemObjectStore",
    "FilesystemStorageOptions",
    "MemoryObjectStore",
    "CustomObjectStore",
    "SuiObjectStore",
    "SuiStorageOptions",
]
