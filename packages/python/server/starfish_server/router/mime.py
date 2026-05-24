"""MIME type matching utilities."""

MIME_JSON = "application/json"


def _mime_match(media_type: str, pattern: str) -> bool:
    """Component-only wildcard match — only a whole ``*`` component is a wildcard.

    Mirrors the TS ``mimeMatch`` (``mime.ts``): ``image/*`` and ``*/*`` match, but a
    partial glob like ``image/p*`` is treated literally (does NOT match ``image/png``).
    This avoids an allowlist over-matching via glob metacharacters.
    """
    m = media_type.split("/")
    p = pattern.split("/")
    type_ = m[0] if len(m) > 0 else ""
    subtype = m[1] if len(m) > 1 else ""
    p_type = p[0] if len(p) > 0 else ""
    p_subtype = p[1] if len(p) > 1 else ""
    if not type_ or not subtype or not p_type or not p_subtype:
        return False
    if p_type != "*" and p_type != type_:
        return False
    if p_subtype != "*" and p_subtype != subtype:
        return False
    return True


def matches_allowed_mime(content_type: str, patterns: list[str]) -> bool:
    """Check if a Content-Type header value matches any of the allowed MIME patterns.

    Strips parameters (e.g. ``; charset=utf-8``) before matching, and matches
    case-insensitively. Supports ``type/*`` and ``*/*`` wildcards (component-only).
    """
    media_type = content_type.split(";")[0].strip().lower()
    if not media_type:
        return False
    return any(_mime_match(media_type, p.lower()) for p in patterns)


def is_json_collection(allowed_mime_types: list[str]) -> bool:
    """Return True if the collection uses the JSON sync protocol."""
    return MIME_JSON in [m.lower() for m in allowed_mime_types]
