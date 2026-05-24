"""Client-side helpers for fetching the server's collection manifest."""


from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class AppendOnlyClientInfo:
    """Append-only configuration exposed via ``GET /config``."""

    type: str | None = None
    """Append-only strategy discriminator. Only ``"by_timestamp"`` is supported today."""

    field: str | None = None
    """Array field name in the stored document. ``None`` means the server default (``"items"``)."""

    persist: bool | None = None
    """``False`` = no storage write (replaces ``queueOnly``). ``None``/``True`` = append to array."""


@dataclass
class CollectionClientInfo:
    """Per-collection metadata returned by ``GET /config``."""

    name: str
    max_body_bytes: int
    encryption: str
    allowed_mime_types: list[str]
    pull_only: bool | None = None
    push_only: bool | None = None
    append_only: AppendOnlyClientInfo | None = None
    ttl_ms: int | None = None
    force_full_fetch: bool | None = None


@dataclass
class NamespaceClientConfig:
    """Collections within a single namespace returned by ``GET /config``."""

    collections: list[CollectionClientInfo] = field(default_factory=list)


@dataclass
class ConfigResponse:
    """Response returned by :func:`fetch_server_config`."""

    collections: list[CollectionClientInfo] = field(default_factory=list)
    namespaces: dict[str, NamespaceClientConfig] | None = None


def _parse_append_only(raw: dict[str, Any] | None) -> AppendOnlyClientInfo | None:
    if raw is None:
        return None
    return AppendOnlyClientInfo(
        type=raw.get("type"),
        field=raw.get("field"),
        persist=raw.get("persist"),
    )


def _parse_collection(raw: dict) -> CollectionClientInfo:
    return CollectionClientInfo(
        name=raw["name"],
        max_body_bytes=raw["maxBodyBytes"],
        encryption=raw["encryption"],
        allowed_mime_types=raw["allowedMimeTypes"],
        pull_only=raw.get("pullOnly") or None,
        push_only=raw.get("pushOnly") or None,
        append_only=_parse_append_only(raw.get("appendOnly")),
        ttl_ms=raw.get("ttlMs"),
        force_full_fetch=raw.get("forceFullFetch") or None,
    )


async def fetch_server_config(
    base_url: str,
    headers: dict[str, str] | None = None,
    *,
    _client: httpx.AsyncClient | None = None,
) -> ConfigResponse:
    """Fetch the server's collection manifest from ``GET {base_url}/config``.

    Args:
        base_url: Base URL of the Starfish server, e.g. ``"https://api.example.com/v1"``.
        headers: Optional request headers, e.g. ``{"Authorization": "Bearer token"}``.

    Returns:
        :class:`ConfigResponse` with the list of visible collections (and namespaces).

    Raises:
        httpx.HTTPStatusError: if the server returns a non-2xx response.
    """
    url = f"{base_url.rstrip('/')}/config"
    if _client is not None:
        resp = await _client.get(url, headers=headers or {})
        resp.raise_for_status()
        data = resp.json()
    else:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers or {})
            resp.raise_for_status()
            data = resp.json()

    collections = [_parse_collection(c) for c in data.get("collections", [])]

    namespaces: dict[str, NamespaceClientConfig] | None = None
    if data.get("namespaces"):
        namespaces = {
            ns_name: NamespaceClientConfig(
                collections=[_parse_collection(c) for c in ns_data.get("collections", [])]
            )
            for ns_name, ns_data in data["namespaces"].items()
        }

    return ConfigResponse(collections=collections, namespaces=namespaces)
