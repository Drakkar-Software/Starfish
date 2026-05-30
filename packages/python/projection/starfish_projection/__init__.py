"""``starfish-projection`` — materialized-view extension.

Public surface: the :class:`Projection` view spec and its outcome types
(:class:`ProjectionUpsert`, :class:`ProjectionDelete`), and
``create_projection_server_plugin`` — a ``ServerPlugin`` whose ``after_write``
hook derives a document into a target collection after each successful push, with
upsert / delete / ignore semantics. Pair the target collection with
``pull_only=True`` so only the projection writes it (clients read/list only).
"""

from starfish_projection.config import (
    Projection,
    ProjectionDelete,
    ProjectionResult,
    ProjectionUpsert,
)


def __getattr__(name: str):
    """Lazy import of ``create_projection_server_plugin`` (keeps the
    ``starfish_server`` import off the hot path for import-only users)."""
    if name == "create_projection_server_plugin":
        from starfish_projection.plugin import create_projection_server_plugin as _p
        return _p
    raise AttributeError(f"module 'starfish_projection' has no attribute {name!r}")


__all__ = [
    "Projection",
    "ProjectionUpsert",
    "ProjectionDelete",
    "ProjectionResult",
    "create_projection_server_plugin",
]
