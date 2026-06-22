"""SpaceAccessError — raised when node/space access is denied."""

from __future__ import annotations


class SpaceAccessError(Exception):
    """Raised when the local access store has no valid credential for a node.

    Attributes:
        space_id: The space whose access was denied.
        node_id:  The specific node (or ``None`` for space-level denial).
    """

    def __init__(
        self,
        space_id: str,
        node_id: str | None = None,
        message: str | None = None,
    ) -> None:
        self.space_id = space_id
        self.node_id = node_id
        if message is None:
            if node_id is not None:
                message = f"No access credential for node {node_id!r} in space {space_id!r}"
            else:
                message = f"No access credential for space {space_id!r}"
        super().__init__(message)
        self.name = "SpaceAccessError"


__all__ = ["SpaceAccessError"]
