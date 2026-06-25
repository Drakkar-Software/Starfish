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
QUERY_LIMIT = "limit"
QUERY_LAST = "last"
QUERY_FULL = "full"

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
# Append rejected because the collection's ``maxItems`` cap is reached.
ERROR_APPEND_LIMIT_EXCEEDED = "append_limit_exceeded"
# Append-only pull rejected: no bound given. A pull MUST declare how much it
# fetches via one of ``?checkpoint=``, ``?limit=``, ``?last=``, or ``?full=true``.
ERROR_PULL_BOUND_REQUIRED = "pull_bound_required"
# Append-only pull rejected: ``?full=true`` combined with a bound
# (``checkpoint``/``limit``/``last``) — contradictory, ``full`` means "everything".
ERROR_FULL_WITH_BOUNDS = "full_with_bounds"
# Append-only pull rejected: ``?full=true`` but the collection has ``allowFull: false``.
ERROR_FULL_NOT_ALLOWED = "full_not_allowed"
# Append-only pull rejected: ``?checkpoint=`` is older than ``maxCheckpointAgeMs``.
ERROR_CHECKPOINT_TOO_OLD = "checkpoint_too_old"
# Batch-pull rejected: ``appendParams`` given for a collection that is not append-only.
ERROR_APPEND_PARAMS_NOT_SUPPORTED = "append_params_not_supported"
# Suffix appended to a document key to namespace its segmented-storage chunks,
# e.g. head ``events/X`` -> chunks under ``events/X__seg/``. A sibling prefix (not
# a child of the head key) so the head can stay a single file even on the
# filesystem backend (no file-vs-directory clash).
APPEND_SEG_SUFFIX = "__seg/"
# Zero-pad width for the ``firstTs`` encoded in a chunk key. The chunk's first
# element ``ts`` is the key, so the lexicographically sorted key list (one
# ``list_keys`` call, no chunk reads) tells the server each chunk's ts range and
# which chunks a ``?checkpoint=`` can skip. 16 digits covers ts well past the
# future-skew bound for centuries.
APPEND_SEG_TS_WIDTH = 16
# Recommended default elements-per-chunk for segmented append-only storage.
APPEND_DEFAULT_CHUNK_SIZE = 10_000

# Protocol
ERROR_HASH_MISMATCH = "hash_mismatch"
CONTENT_TYPE_JSON = "application/json"
