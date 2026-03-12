"""Storage backends for the Starfish sync protocol."""

from starfish_server.storage.memory import MemoryObjectStore, CustomObjectStore

__all__ = ["MemoryObjectStore", "CustomObjectStore"]
