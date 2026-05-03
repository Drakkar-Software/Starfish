"""Shared constants for the Starfish sync protocol."""

# Roles
ROLE_PUBLIC = "public"
ROLE_SELF = "self"

# Access operations
OP_READ = "read"
OP_WRITE = "write"

# Encryption modes
ENCRYPTION_NONE = "none"
ENCRYPTION_IDENTITY = "identity"
ENCRYPTION_SERVER = "server"
ENCRYPTION_DELEGATED = "delegated"
ENCRYPTION_GROUP = "group"

# Route actions
ACTION_PULL = "pull"
ACTION_PUSH = "push"
ACTION_LIST = "list"

# Path params
IDENTITY_PARAM = "{identity}"
IDENTITY_KEY = "identity"
QUERY_CHECKPOINT = "checkpoint"

# HKDF info strings (domain separation)
HKDF_INFO_DEFAULT = "starfish-data"
HKDF_INFO_IDENTITY = "starfish-identity-data"
HKDF_INFO_SERVER = "starfish-server-data"

# Config
DEFAULT_CONFIG_KEY = "__sync__/config.json"

# AppendOnly
APPEND_DEFAULT_FIELD = "items"

# Protocol
ERROR_HASH_MISMATCH = "hash_mismatch"
CONTENT_TYPE_JSON = "application/json"
