"""Protocol wire-field-name constants.

Field names that travel on the wire and are read/written by string key on
untyped JSON objects (request bodies, stored documents, pulled elements) are
defined here ONCE so the TypeScript and Python implementations cannot drift — a
typo or a one-sided rename is a test failure, not a silent interop break. Typed
``TypedDict`` declarations (e.g. ``AppendAuthor``, ``AppendElement``) keep these
as declared keys; this module is for the places that index a ``dict`` by string.

Mirrored byte-for-byte by ``packages/ts/protocol/src/constants.ts``.
"""

# Author proof attached to a signed append/push: the author's public key (hex).
AUTHOR_PUBKEY_FIELD = "authorPubkey"

# Author proof attached to a signed append/push: base64 signature over the data.
AUTHOR_SIGNATURE_FIELD = "authorSignature"

# Request-body field carrying the write payload (``{data}`` / ``{data, baseHash}``).
DATA_FIELD = "data"

# Request-body field carrying a client-supplied element/document timestamp (ms).
TS_FIELD = "ts"

# Request-body field carrying the optimistic-concurrency base hash (merge push).
BASE_HASH_FIELD = "baseHash"

# Action prefix on a push endpoint path. The storage ``document_key`` is the push
# ``path`` with this prefix stripped (the namespace lives only in the URL), and the
# author signature binds to that ``document_key``.
PUSH_PATH_PREFIX = "/push/"

# HTTP header names of the v3 request-auth contract. Defined here so the client
# (which sends them) and the server cap-resolver (which reads them) cannot drift.
HEADER_AUTHORIZATION = "Authorization"
HEADER_SIG = "X-Starfish-Sig"
HEADER_TS = "X-Starfish-Ts"
HEADER_NONCE = "X-Starfish-Nonce"
HEADER_PUB = "X-Starfish-Pub"
HEADER_CONTENT_TYPE = "Content-Type"
HEADER_ACCEPT = "Accept"

# The non-simple request headers a browser must see listed in the
# ``Access-Control-Allow-Headers`` CORS response so a cross-origin authenticated
# request is not blocked by the preflight. ``X-Requested-With`` is included
# because clients may send it. Built from the ``HEADER_*`` constants above so the
# CORS allow-list and the actual header names can never drift apart.
CORS_ALLOW_HEADERS = [
    HEADER_AUTHORIZATION,
    HEADER_CONTENT_TYPE,
    HEADER_SIG,
    HEADER_TS,
    HEADER_NONCE,
    HEADER_PUB,
    "X-Requested-With",
]

# Apache Parquet MIME types.
# Mirrored byte-for-byte by ``packages/ts/protocol/src/constants.ts``.

# Canonical MIME type for Apache Parquet files.
# Use this when pushing Parquet data so the S3 object carries the correct
# ContentType (readable by DuckDB, CDNs, and standard tooling).
PARQUET_MIME_TYPE = "application/vnd.apache.parquet"

# Accept-list for a Parquet push collection.
# Many Parquet writers emit ``application/octet-stream``; ``application/x-parquet``
# covers older tooling. Use this list as ``allowed_mime_types`` in a server
# collection config that accepts Parquet uploads.
PARQUET_MIME_TYPES = (
    "application/vnd.apache.parquet",
    "application/x-parquet",
    "application/octet-stream",
)

__all__ = [
    "AUTHOR_PUBKEY_FIELD",
    "AUTHOR_SIGNATURE_FIELD",
    "DATA_FIELD",
    "TS_FIELD",
    "BASE_HASH_FIELD",
    "PUSH_PATH_PREFIX",
    "HEADER_AUTHORIZATION",
    "HEADER_SIG",
    "HEADER_TS",
    "HEADER_NONCE",
    "HEADER_PUB",
    "HEADER_CONTENT_TYPE",
    "HEADER_ACCEPT",
    "CORS_ALLOW_HEADERS",
    "PARQUET_MIME_TYPE",
    "PARQUET_MIME_TYPES",
]
