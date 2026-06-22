"""Server companion for ``starfish-spaces``.

Exports two factory functions:

- :func:`create_spaces_role_enricher` — a ``RoleEnricher`` that grants
  ``'space:owner'`` / ``'space:member'`` from the space's ``_access`` registry doc.

- :func:`create_spaces_directory_server_plugin` — a ``ServerPlugin`` with an
  ``after_write`` hook that maintains the global public-object directory by
  projecting the ``public`` nodes from each space's object index.

These are **lazy-imported** from :mod:`starfish_spaces.__init__` via
``__getattr__`` so client-only users do not import ``starfish_server``.
"""

from __future__ import annotations

import json
from typing import Any, Optional, TYPE_CHECKING

from starfish_sharing import make_registry_role_enricher

from starfish_spaces.config import SpaceLayout
from starfish_spaces.layout import default_space_layout

if TYPE_CHECKING:
    pass


# ── RoleEnricher ──────────────────────────────────────────────────────────────


def create_spaces_role_enricher(
    store: Any,
    layout: SpaceLayout = default_space_layout,
) -> Any:
    """Create a ``RoleEnricher`` that grants ``'space:owner'`` / ``'space:member'``.

    Args:
        store:  Any object with ``async get_string(key: str) -> str | None``.
        layout: The :class:`SpaceLayout` to use (default: :data:`default_space_layout`).

    Returns:
        A callable ``RoleEnricher`` (from ``starfish_sharing``).
    """
    # The raw storage key for the _access doc (no /pull/ prefix — store keys are bare).
    raw_pull_path = layout.space_access_pull("{id}")
    registry_path = raw_pull_path.lstrip("/").removeprefix("pull/")

    return make_registry_role_enricher(
        store,
        id_param="spaceId",
        registry_path=registry_path,
        owner_role="space:owner",
        member_role="space:member",
        allow_tofu=True,
    )


# ── Directory server plugin ───────────────────────────────────────────────────


def create_spaces_directory_server_plugin(
    store: Any,
    layout: SpaceLayout = default_space_layout,
) -> Any:
    """Create a ``ServerPlugin`` with an ``after_write`` hook.

    The hook fires on writes to the ``objindex`` collection at
    ``spaces/{spaceId}/objects/_index``. It:

    1. Reads the index doc's ``objects`` array from the event body.
    2. Filters for nodes where ``access == 'public'`` (public+enc is invalid).
    3. Builds a directory entry bucket for this space.
    4. Reads + merges the current public directory doc.
    5. Writes the updated directory doc to ``_index/objects/public``.

    Errors are logged and swallowed — a hook failure must not break client writes.
    """
    dir_key = layout.object_dir_pull("public").lstrip("/").removeprefix("pull/")

    async def after_write(event: Any) -> None:
        try:
            collection = getattr(event, "collection", None) or (event.get("collection") if isinstance(event, dict) else None)
            if collection != "objindex":
                return

            params = getattr(event, "params", {}) or (event.get("params", {}) if isinstance(event, dict) else {})
            space_id = params.get("spaceId") if isinstance(params, dict) else None
            if not space_id:
                return

            body = getattr(event, "body", {}) or (event.get("body", {}) if isinstance(event, dict) else {})
            objects = (body.get("objects", []) if isinstance(body, dict) else []) or []
            if not isinstance(objects, list):
                return

            public_nodes = [
                {
                    "id": n.get("id"),
                    "type": n.get("type"),
                    "title": n.get("title"),
                    **({"emoji": n["emoji"]} if "emoji" in n else {}),
                    "updatedAt": n.get("updatedAt"),
                }
                for n in objects
                if isinstance(n, dict) and n.get("access") == "public" and not n.get("enc")
            ]

            # Read current directory doc.
            dir_doc: dict[str, Any] = {}
            try:
                raw = await store.get_string(dir_key)
                if raw:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        candidate = parsed.get("data", parsed)
                        if isinstance(candidate, dict):
                            dir_doc = candidate
            except Exception:
                dir_doc = {}

            # Merge this space's bucket.
            if public_nodes:
                dir_doc = {**dir_doc, space_id: {"nodes": public_nodes}}
            else:
                dir_doc = {k: v for k, v in dir_doc.items() if k != space_id}

            await store.put_string(dir_key, json.dumps({"v": 1, **dir_doc}))

        except Exception as exc:
            import logging
            logging.getLogger(__name__).error(
                "[starfish-spaces] directory after_write hook failed: %s", exc
            )

    return {
        "name": "starfish-spaces-directory",
        "after_write": after_write,
    }


__all__ = [
    "create_spaces_role_enricher",
    "create_spaces_directory_server_plugin",
]
