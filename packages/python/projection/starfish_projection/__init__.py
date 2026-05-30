"""``starfish-projection`` — incremental-list extension.

Public surface: the :class:`Projection` list spec and its outcome types
(:class:`ProjectionSet`, :class:`ProjectionRemove`), and
``create_projection_server_plugin`` — a ``ServerPlugin`` whose ``after_write``
hook folds each source write into a single target list document (append /
update-in-place / remove). Clients pull that one document to read the whole list.
Pair the target collection with ``pull_only=True`` so only the projection writes
it (clients read it only).
"""

from starfish_projection.config import (
    Projection,
    ProjectionOp,
    ProjectionRemove,
    ProjectionSet,
    ProjectionTarget,
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
    "ProjectionSet",
    "ProjectionRemove",
    "ProjectionOp",
    "ProjectionTarget",
    "create_projection_server_plugin",
]
