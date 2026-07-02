"""Parquet / DuckDB collection helpers.

A **Parquet collection** is a binary collection (no ``application/json`` in
``allowed_mime_types``) whose bytes are Apache Parquet files generated
client-side, pushed to the server, stored verbatim on S3, and queried
directly by DuckDB via the ``httpfs`` extension — without any server
round-trip for reads.

All transport, auth, rate limiting, and S3 storage is provided by the
existing binary-collection machinery.  This module adds:

- :func:`create_parquet_collection` — builds a ``CollectionConfig`` preset
  with configurable read/write auth and rate limiting.
- :func:`duckdb_read_parquet_sql` — generates DuckDB SQL to query the stored
  Parquet files via ``s3://``.

Example::

    from starfish_server import (
        create_parquet_collection,
        duckdb_read_parquet_sql,
        resolve_document_key,
    )
    from starfish_server.storage.s3 import S3StorageOptions

    col = create_parquet_collection(
        name="datasets",
        storage_path="datasets/{owner}/{dataset}",
        read="public",         # DuckDB reads S3 directly — no auth on reads
        write="authenticated",
    )

    s3_opts = S3StorageOptions(
        endpoint="http://localhost:9000",
        bucket="starfish",
        access_key_id="<access-key-id>",
        secret_access_key="<secret-access-key>",
    )
    key = resolve_document_key("datasets/{owner}/{dataset}", {"owner": "alice", "dataset": "sales.parquet"})
    result = duckdb_read_parquet_sql(s3=s3_opts, key=key)
    # result.sql is safe to log; result.runnable_sql (contains the secret) runs in DuckDB
    print(result.runnable_sql)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Union
from urllib.parse import urlparse

from starfish_protocol.constants import PARQUET_MIME_TYPES, PARQUET_MIME_TYPE
from starfish_server.config.schema import CollectionConfig, CollectionRateLimitConfig
from starfish_server.constants import ROLE_PUBLIC
from starfish_server.router.route_builder import resolve_document_key

__all__ = [
    "ParquetAccessMode",
    "create_parquet_collection",
    "create_sealed_parquet_collection",
    "DuckdbParquetSqlResult",
    "duckdb_read_parquet_sql",
    "PARQUET_MIME_TYPE",
    "PARQUET_MIME_TYPES",
    "resolve_document_key",
]

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

ParquetAccessMode = Union[Literal["public", "authenticated", "none"], list[str]]
"""Controls who may read or write a Parquet collection.

- ``"public"`` — no authentication required (``ROLE_PUBLIC``).
- ``"authenticated"`` — requires a valid cap-cert scoped to this collection
  (``cap:read:<name>`` / ``cap:write:<name>``).
- ``"none"`` — the corresponding endpoint (pull or push) is **disabled**.
- ``list[str]`` — custom role list, passed verbatim.
"""


# ---------------------------------------------------------------------------
# create_parquet_collection
# ---------------------------------------------------------------------------


def create_parquet_collection(
    *,
    name: str,
    storage_path: str,
    read: ParquetAccessMode = "public",
    write: ParquetAccessMode = "authenticated",
    rate_limit: "Literal['none'] | CollectionRateLimitConfig" = "none",
    max_body_bytes: int = 256 * 1024 * 1024,
    cache_duration_ms: int | None = None,
) -> CollectionConfig:
    """Build a :class:`~starfish_server.config.schema.CollectionConfig` preset
    for Apache Parquet / DuckDB workflows.

    The resulting collection:

    - Accepts all common Parquet MIME types (``allowed_mime_types = PARQUET_MIME_TYPES``).
    - Forces ``encryption="none"`` — client-side delegated encryption stores
      ciphertext on S3, which DuckDB cannot decode.
    - Enables ``listable`` automatically when the last ``storage_path`` segment
      is a ``{param}``, so DuckDB can glob all files under a prefix via
      ``read_parquet('s3://…/*.parquet')``.
    - Maps ``read`` / ``write`` to the correct role arrays and
      ``push_only`` / ``pull_only`` flags.

    Args:
        name: Unique collection name.  Used to derive cap-cert role names when
            the access mode is ``"authenticated"``.
        storage_path: Template with ``{param}`` placeholders
            (e.g. ``"datasets/{owner}/{dataset}"``).  Each resolved placeholder
            is part of the S3 object key.
        read: Who may pull (read) from this collection.  Defaults to
            ``"public"`` because DuckDB typically reads S3 directly.
        write: Who may push (write) to this collection.  Defaults to
            ``"authenticated"``.
        rate_limit: ``"none"`` (default, unmetered) or a
            :class:`~starfish_server.config.schema.CollectionRateLimitConfig`
            object for per-action / per-identity rate limiting.
        max_body_bytes: Maximum push body size.  Default 256 MiB.
        cache_duration_ms: ``Cache-Control: max-age`` duration (ms) added to
            pull responses.

    Raises:
        ValueError: If both ``read`` and ``write`` are ``"none"``.

    Example::

        col = create_parquet_collection(
            name="sales",
            storage_path="analytics/{owner}/{report}",
            read="public",
            write="authenticated",
        )
    """
    if read == "none" and write == "none":
        raise ValueError(
            f'create_parquet_collection("{name}"): both read and write are "none" — '
            "the collection would be completely inaccessible. "
            'Set at least one to "public", "authenticated", or a custom role list.'
        )

    read_roles = _resolve_access_roles(name, read, "read")
    write_roles = _resolve_access_roles(name, write, "write")

    push_only = True if read == "none" else None
    pull_only = True if write == "none" else None

    # Auto-enable listable when the last storage_path segment is a {param} so
    # DuckDB can glob all objects under the prefix.
    listable: bool | None = True if _is_last_segment_param(storage_path) else None

    resolved_rate_limit = None if rate_limit == "none" else rate_limit

    kwargs: dict = {
        "name": name,
        "storagePath": storage_path,
        "readRoles": read_roles,
        "writeRoles": write_roles,
        "encryption": "none",
        "maxBodyBytes": max_body_bytes,
        "allowedMimeTypes": list(PARQUET_MIME_TYPES),
        "rateLimit": resolved_rate_limit,
    }
    if listable is not None:
        kwargs["listable"] = listable
    if cache_duration_ms is not None:
        kwargs["cacheDurationMs"] = cache_duration_ms
    if push_only:
        kwargs["pushOnly"] = True
    if pull_only:
        kwargs["pullOnly"] = True

    return CollectionConfig(**kwargs)


# ---------------------------------------------------------------------------
# create_sealed_parquet_collection
# ---------------------------------------------------------------------------


def create_sealed_parquet_collection(
    *,
    name: str,
    storage_path: str,
    read: ParquetAccessMode = "authenticated",
    write: ParquetAccessMode = "authenticated",
    rate_limit: "Literal['none'] | CollectionRateLimitConfig" = "none",
    max_body_bytes: int = 256 * 1024 * 1024,
    cache_duration_ms: int | None = None,
) -> CollectionConfig:
    """Build a :class:`~starfish_server.config.schema.CollectionConfig` preset
    for **client-sealed** Parquet datasets (E2EE / end-to-end encrypted).

    Use this when you want the server to store opaque ciphertext rather than
    readable Parquet bytes.  The client AES-256-GCM-seals the Parquet file under
    the space keyring CEK (AAD bound to the storage path) before uploading, and
    unseals it after downloading.  The server and S3 bucket never see plaintext.

    **Trade-off:** because the stored bytes are ciphertext, they are **not**
    valid Parquet files — DuckDB cannot read them via ``read_parquet('s3://…')``.
    Use :func:`create_parquet_collection` instead when server-side / S3-direct
    DuckDB querying is the goal; use this variant when the priority is E2EE and
    clients query locally (e.g. DuckDB-WASM after unsealing).

    Compared to :func:`create_parquet_collection`, the differences are:

    - ``read`` defaults to ``"authenticated"`` (not ``"public"``) — E2EE data
      should not be world-downloadable by default.
    - ``allowed_mime_types=["application/octet-stream"]`` — the sealed bytes are
      opaque binary, not Parquet MIME typed.

    Args:
        name: Unique collection name.
        storage_path: Template with ``{param}`` placeholders.
        read: Who may pull.  Defaults to ``"authenticated"``.
        write: Who may push.  Defaults to ``"authenticated"``.
        rate_limit: ``"none"`` (default) or a
            :class:`~starfish_server.config.schema.CollectionRateLimitConfig`.
        max_body_bytes: Maximum push body size.  Default 256 MiB.
        cache_duration_ms: ``Cache-Control: max-age`` duration (ms).

    Raises:
        ValueError: If both ``read`` and ``write`` are ``"none"``.

    Example::

        col = create_sealed_parquet_collection(
            name="private-datasets",
            storage_path="spaces/{spaceId}/objects/parquet-enc/{objectId}",
            read=["space:member"],
            write=["space:member"],
            max_body_bytes=67_108_864,
        )
    """
    if read == "none" and write == "none":
        raise ValueError(
            f'create_sealed_parquet_collection("{name}"): both read and write are "none" — '
            "the collection would be completely inaccessible. "
            'Set at least one to "public", "authenticated", or a custom role list.'
        )

    # Build via create_parquet_collection (same logic, same fields), then override
    # only the MIME allowlist — sealed bytes are opaque binary, not Parquet MIME typed.
    base = create_parquet_collection(
        name=name,
        storage_path=storage_path,
        read=read,
        write=write,
        rate_limit=rate_limit,
        max_body_bytes=max_body_bytes,
        cache_duration_ms=cache_duration_ms,
    )
    return base.model_copy(update={"allowed_mime_types": ["application/octet-stream"]})


# ---------------------------------------------------------------------------
# duckdb_read_parquet_sql
# ---------------------------------------------------------------------------


@dataclass
class DuckdbParquetSqlResult:
    """DuckDB SQL statements to query a Parquet file from S3."""

    uri: str
    """Full ``s3://…`` URI passed to ``read_parquet()``."""

    setup_sql: str
    """``INSTALL httpfs;\\nLOAD httpfs;`` — run once per DuckDB session."""

    config_sql: str
    """``SET s3_*`` configuration statements, EXCLUDING the secret access key.
    Safe to log — the live secret lives only in :attr:`credential_sql`."""

    credential_sql: str
    """``SET s3_secret_access_key='…';`` — **contains a live S3 secret**.
    Returned separately so it can be run without folding the credential into
    :attr:`sql`. NEVER log this field."""

    read_sql: str
    """``SELECT * FROM read_parquet('…')`` statement."""

    sql: str
    """Redactable script (setup + config + read) with the secret access key
    OMITTED — safe to log. Because it lacks the credential it is **not**
    runnable on its own: run :attr:`credential_sql` in the same DuckDB session,
    or use :attr:`runnable_sql`."""

    runnable_sql: str
    """Full runnable script (setup + config + credential + read) INCLUDING the
    secret access key. **Contains a live S3 secret** — NEVER log this field."""


def duckdb_read_parquet_sql(
    *,
    s3,  # S3StorageOptions — not imported to avoid circular dep / optional S3 extra
    key: str,
    glob: bool = False,
    force_path_style: bool | None = None,
) -> DuckdbParquetSqlResult:
    """Generate DuckDB SQL to query a Parquet file (or prefix glob) stored on S3.

    No DuckDB package is required — execute the returned :attr:`~DuckdbParquetSqlResult.sql`
    yourself (DuckDB CLI, Python ``duckdb`` package, DuckDB-WASM, etc.).

    Args:
        s3: An :class:`~starfish_server.storage.s3.S3StorageOptions` instance
            (same object passed to ``S3ObjectStore``).
        key: Resolved S3 object key — use :func:`resolve_document_key` to
            derive it from ``storage_path`` and its ``{param}`` values.
        glob: When ``True``, appends ``/*.parquet`` to ``key``, producing a
            glob that reads all Parquet objects under the prefix.  Use with
            ``listable`` collections whose last path segment is per-file.
        force_path_style: Override the URL style.  When ``None`` (default),
            reads ``s3.force_path_style`` from the options object (``True`` if
            not set).  Pass ``True``/``False`` to override explicitly.

    Example::

        from starfish_server import resolve_document_key, duckdb_read_parquet_sql
        from starfish_server.storage.s3 import S3StorageOptions

        s3 = S3StorageOptions(endpoint="http://localhost:9000", bucket="data",
                              access_key_id="<access-key-id>", secret_access_key="<secret-access-key>")
        key = resolve_document_key("analytics/{owner}/{report}",
                                   {"owner": "alice", "report": "q1.parquet"})
        result = duckdb_read_parquet_sql(s3=s3, key=key)
        # result.sql is safe to log; result.runnable_sql (contains the secret) runs in DuckDB

        # Glob all reports by alice
        prefix = resolve_document_key("analytics/{owner}", {"owner": "alice"})
        result = duckdb_read_parquet_sql(s3=s3, key=prefix, glob=True)
        # → SELECT * FROM read_parquet('s3://data/analytics/alice/*.parquet')
    """
    parsed = urlparse(s3.endpoint)
    use_ssl = parsed.scheme == "https"
    host = parsed.netloc  # e.g. "localhost:9000" or "s3.amazonaws.com"
    # force_path_style kwarg overrides; falls back to s3.force_path_style (default True).
    effective_path_style = force_path_style if force_path_style is not None else getattr(s3, "force_path_style", True)
    url_style = "path" if effective_path_style else "vhost"

    def sq(v: str) -> str:
        return v.replace("'", "''")

    normalized_key = key.removesuffix("/*.parquet").rstrip("/")
    resolved_key = (normalized_key + "/*.parquet" if normalized_key else "*.parquet") if glob else key
    uri = f"s3://{sq(s3.bucket)}/{sq(resolved_key)}"

    setup_sql = "INSTALL httpfs;\nLOAD httpfs;"

    # config_sql deliberately OMITS s3_secret_access_key so it (and ``sql``) stay
    # safe to log. The secret is emitted only in the separate ``credential_sql``.
    config_lines = [
        f"SET s3_endpoint='{sq(host)}';",
        f"SET s3_access_key_id='{sq(s3.access_key_id)}';",
        f"SET s3_region='{sq(s3.region)}';",
        f"SET s3_url_style='{url_style}';",
        f"SET s3_use_ssl={str(use_ssl).lower()};",
    ]
    config_sql = "\n".join(config_lines)

    # SECURITY: this statement embeds the live S3 secret access key. It is
    # returned in its own field and never folded into ``sql``, so callers can run
    # it in the DuckDB session without logging it. NEVER log ``credential_sql``.
    credential_sql = f"SET s3_secret_access_key='{sq(s3.secret_access_key)}';"

    read_sql = f"SELECT * FROM read_parquet('{uri}');"

    # Redactable (no secret) — safe to log; not runnable without credential_sql.
    sql = "\n".join([setup_sql, config_sql, read_sql])
    # Full runnable script INCLUDING the secret — NEVER log.
    runnable_sql = "\n".join([setup_sql, config_sql, credential_sql, read_sql])

    return DuckdbParquetSqlResult(
        uri=uri,
        setup_sql=setup_sql,
        config_sql=config_sql,
        credential_sql=credential_sql,
        read_sql=read_sql,
        sql=sql,
        runnable_sql=runnable_sql,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_access_roles(name: str, mode: ParquetAccessMode, op: str) -> list[str]:
    if mode == "public":
        return [ROLE_PUBLIC]
    if mode == "authenticated":
        return [f"cap:{op}:{name}"]
    if mode == "none":
        # Provide a placeholder role that is never checked at runtime — the
        # corresponding endpoint is disabled via push_only / pull_only.
        return [f"cap:{op}:{name}"]
    # Custom list[str] — verbatim pass-through.
    return list(mode)  # type: ignore[arg-type]


def _is_last_segment_param(storage_path: str) -> bool:
    """Return True when the last non-empty segment of storage_path is a {param}."""
    last_segment = storage_path.rstrip("/").rsplit("/", 1)[-1]
    return last_segment.startswith("{") and last_segment.endswith("}")
