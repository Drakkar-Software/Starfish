"""``starfish-replica`` — primary→replica replication extension.

Public surface: :class:`ReplicaManager` (the sync engine), the replica config
types (:class:`RemoteConfig`/:class:`WriteMode`/:class:`SyncTrigger`/
:class:`RemoteCollection`), :func:`validate_replica_config`, and
:func:`create_replica_server_plugin` — a ``ServerPlugin`` whose
``before_pull``/``intercept_push`` hooks enforce write modes and proxy
push-through writes, and whose ``shutdown`` hook stops the sync timers.
"""

from starfish_replica.config import (
    RemoteCollection,
    RemoteConfig,
    SyncTrigger,
    WriteMode,
)
from starfish_replica.manager import ReplicaManager
from starfish_replica.plugin import ReplicaServerPlugin, create_replica_server_plugin
from starfish_replica.validate import validate_replica_config

__all__ = [
    "RemoteCollection",
    "RemoteConfig",
    "SyncTrigger",
    "WriteMode",
    "ReplicaManager",
    "ReplicaServerPlugin",
    "create_replica_server_plugin",
    "validate_replica_config",
]
