// Roles
export const ROLE_PUBLIC = "public"
export const ROLE_SELF = "self"

// Access operations
export const OP_READ = "read"
export const OP_WRITE = "write"

// Encryption modes
export const ENCRYPTION_NONE = "none"
export const ENCRYPTION_IDENTITY = "identity"
export const ENCRYPTION_SERVER = "server"
export const ENCRYPTION_DELEGATED = "delegated"
export const ENCRYPTION_GROUP = "group"

// Route actions
export const ACTION_PULL = "pull"
export const ACTION_PUSH = "push"
export const ACTION_LIST = "list"

// Path params
export const IDENTITY_PARAM = "{identity}"
export const IDENTITY_KEY = "identity"
export const QUERY_CHECKPOINT = "checkpoint"

// HKDF info strings (domain separation)
export const HKDF_INFO_DEFAULT = "starfish-data"
export const HKDF_INFO_IDENTITY = "starfish-identity-data"
export const HKDF_INFO_SERVER = "starfish-server-data"

// Config
export const DEFAULT_CONFIG_KEY = "__sync__/config.json"

// AppendOnly
export const APPEND_DEFAULT_FIELD = "items"

// Protocol
export const ERROR_HASH_MISMATCH = "hash_mismatch"
export const CONTENT_TYPE_JSON = "application/json"
