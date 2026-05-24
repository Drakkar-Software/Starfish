"""Shared constants for the Starfish sync protocol."""

# Roles
ROLE_PUBLIC = "public"
ROLE_SELF = "self"
# Synthesized for a self-signed device cap (iss == sub) — i.e. the root device,
# as opposed to a paired/delegated device or a member. Collections marked
# ``rootOnly`` require this role.
ROLE_ROOT_DEVICE = "device:root"

# Access operations
OP_READ = "read"
OP_WRITE = "write"

# Encryption modes
ENCRYPTION_NONE = "none"
ENCRYPTION_DELEGATED = "delegated"

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

# Config
DEFAULT_CONFIG_KEY = "__sync__/config.json"

# AppendOnly
APPEND_DEFAULT_FIELD = "items"
# Max clock skew (ms) a client-supplied append `ts` may run ahead of the server
# clock. Bounds the monotonic counter so a writer can't poison the log's
# timestamp space (and detach it from wall-clock) with a far-future `ts`.
APPEND_MAX_FUTURE_TS_SKEW_MS = 300_000

# Protocol
ERROR_HASH_MISMATCH = "hash_mismatch"
CONTENT_TYPE_JSON = "application/json"
