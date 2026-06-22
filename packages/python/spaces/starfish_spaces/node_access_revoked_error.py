"""NodeAccessRevokedError — raised when the server returns 403 on a node keyring pull."""

from __future__ import annotations


class NodeAccessRevokedError(Exception):
    """Raised when the server returns 403 on a node keyring fetch, indicating
    the requester's access to this node was revoked (e.g. the desk archived the
    ticket).

    This is a standalone class, NOT a subclass of :class:`SpaceAccessError`,
    so existing ``except SpaceAccessError`` soft-paths do not swallow it.

    Attributes:
        space_id: The space containing the revoked node.
        node_id:  The node whose access was revoked.
    """

    def __init__(self, space_id: str, node_id: str) -> None:
        self.space_id = space_id
        self.node_id = node_id
        super().__init__(f"Node {node_id!r} access revoked in space {space_id!r}")
        self.name = "NodeAccessRevokedError"


__all__ = ["NodeAccessRevokedError"]
