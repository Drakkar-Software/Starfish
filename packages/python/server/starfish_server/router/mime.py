"""MIME type matching utilities."""

import fnmatch

MIME_JSON = "application/json"


def matches_allowed_mime(content_type: str, patterns: list[str]) -> bool:
    """Check if a Content-Type header value matches any of the allowed MIME patterns.

    Strips parameters (e.g. ``; charset=utf-8``) before matching.
    Supports wildcard patterns like ``image/*`` via :mod:`fnmatch`.
    """
    media_type = content_type.split(";")[0].strip().lower()
    if not media_type:
        return False
    return any(fnmatch.fnmatch(media_type, p.lower()) for p in patterns)


def is_json_collection(allowed_mime_types: list[str]) -> bool:
    """Return True if the collection uses the JSON sync protocol."""
    return MIME_JSON in [m.lower() for m in allowed_mime_types]
