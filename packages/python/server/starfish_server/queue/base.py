"""Abstract base class for queue backends."""

from abc import ABC, abstractmethod


class AbstractQueue(ABC):
    """Publish-only queue interface for emitting data-change events.

    Implementations must provide :meth:`publish`.  The :meth:`connect` and
    :meth:`close` lifecycle hooks have default no-ops — override them only
    when the backend requires explicit connection management (e.g. NATS).
    """

    async def connect(self) -> None:
        """Establish a connection to the queue backend.

        Override for network-backed implementations.  The default is a no-op.
        """

    @abstractmethod
    async def publish(self, subject: str, payload: bytes) -> None:
        raise NotImplementedError("publish must be implemented")

    async def close(self) -> None:
        """Tear down the connection.  Safe to call multiple times.

        Override for network-backed implementations.  The default is a no-op.
        """
