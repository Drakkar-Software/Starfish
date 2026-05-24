// Roles
export const ROLE_PUBLIC = "public"
export const ROLE_SELF = "self"
/**
 * Synthesized for a self-signed device cap (`iss === sub`) — i.e. the root
 * device, as opposed to a paired/delegated device or a member. Collections
 * marked `rootOnly` require this role.
 */
export const ROLE_ROOT_DEVICE = "device:root"

// Access operations
export const OP_READ = "read"
export const OP_WRITE = "write"

// Encryption modes
export const ENCRYPTION_NONE = "none"
export const ENCRYPTION_DELEGATED = "delegated"

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

// Config
export const DEFAULT_CONFIG_KEY = "__sync__/config.json"

// AppendOnly
export const APPEND_DEFAULT_FIELD = "items"
/** Max clock skew (ms) a client-supplied append `ts` may run ahead of the server
 *  clock. Bounds the monotonic counter so a writer can't poison the log's
 *  timestamp space (and detach it from wall-clock) with a far-future `ts`. */
export const APPEND_MAX_FUTURE_TS_SKEW_MS = 300_000

// Protocol
export const ERROR_HASH_MISMATCH = "hash_mismatch"
export const CONTENT_TYPE_JSON = "application/json"
