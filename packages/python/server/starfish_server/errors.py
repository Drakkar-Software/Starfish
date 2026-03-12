"""Error types for the Starfish sync protocol."""



class StartupError(Exception):
    """Raised when the server fails to start due to invalid configuration."""


class AuthError(Exception):
    """Raised on authentication or authorization failure."""

    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


class ConflictError(Exception):
    """Raised when a push conflicts with the current document state."""

    def __init__(self, doc_id: str) -> None:
        super().__init__(f"Conflict on document: {doc_id}")
        self.doc_id = doc_id


class NotFoundError(Exception):
    """Raised when a requested key is not found."""

    def __init__(self, key: str) -> None:
        super().__init__(f"Not found: {key}")
        self.key = key
