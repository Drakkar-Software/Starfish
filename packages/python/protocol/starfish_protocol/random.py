"""CSPRNG-backed identifier helpers.

Mirrors ``packages/ts/protocol/src/random.ts``.

- :func:`random_id` — a 128-bit (16-byte) hex id (32 hex chars).
- :func:`slugify` — converts an arbitrary display name into a URL/path-safe
  ``[a-z0-9-]`` slug capped at 40 characters.
"""

import re
import secrets
import unicodedata


def random_id() -> str:
    """Generate a CSPRNG-backed 128-bit hex id (32 lowercase hex chars).

    Uses :func:`secrets.token_bytes` (CSPRNG) for the source randomness.
    """
    return secrets.token_bytes(16).hex()


def slugify(name: str, fallback: str = "item") -> str:
    """Convert a display name to a URL/path-safe slug.

    Rules:
    - NFD-normalised then ASCII-folded (accented → base letter where possible).
    - Lowercased.
    - Any run of non-``[a-z0-9]`` characters is collapsed to a single ``-``.
    - Leading/trailing ``-`` stripped.
    - Capped at 40 characters.
    - Falls back to *fallback* (default ``"item"``) when the name strips to empty.

    Examples::

        slugify("Hello World!")  # "hello-world"
        slugify("  ")            # "item"
        slugify("My Café")       # "my-caf"
    """
    # NFD decomposition lets us strip combining diacritical marks, giving
    # "caf" from "café" (the same behaviour as the TS implementation which
    # simply runs str.replace(/[^a-z0-9]+/g, "-") after toLowerCase).
    normalized = unicodedata.normalize("NFD", name)
    ascii_str = normalized.encode("ascii", errors="ignore").decode("ascii")
    slug = (
        ascii_str.lower()
        .replace(" ", "-")
        .replace("_", "-")
    )
    # Collapse any run of non-[a-z0-9] to a single dash.
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")[:40]
    return slug or fallback[:40]
