"""``starfish-replica`` — primary→replica replication extension.

Public surface: :class:`ReplicaManager` (the sync engine), the replica config
types (:class:`RemoteConfig`/:class:`WriteMode`/:class:`SyncTrigger`/
:class:`RemoteCollection`), :func:`validate_replica_config`, and
:func:`create_replica_server_plugin` — a ``ServerPlugin`` whose
``before_pull``/``intercept_push`` hooks enforce write modes and proxy
push-through writes, and whose ``shutdown`` hook stops the sync timers. For
authenticated replicas, :class:`ReplicaAuth` is an ``httpx.Auth`` that signs
each outgoing pull/push request with a self-signed device cap-cert.
"""

from starfish_replica.auth import ReplicaAuth
from starfish_replica.channel import (
    REPLICATOR_CTX,
    ChannelSchedule,
    ReplicaCallContext,
    ReplicaChannel,
    ScheduledChannel,
)
from starfish_replica.config import (
    RemoteCollection,
    RemoteConfig,
    SyncTrigger,
    WriteMode,
)
from starfish_replica.http_channel import HttpReplicaChannel
from starfish_replica.manager import ReplicaManager
from starfish_replica.plugin import ReplicaServerPlugin, create_replica_server_plugin
from starfish_replica.scheduler import ChannelScheduler
from starfish_replica.validate import validate_replica_config

__all__ = [
    "ReplicaAuth",
    "RemoteCollection",
    "RemoteConfig",
    "SyncTrigger",
    "WriteMode",
    "ReplicaManager",
    "ChannelScheduler",
    "ReplicaChannel",
    "ReplicaCallContext",
    "REPLICATOR_CTX",
    "ChannelSchedule",
    "ScheduledChannel",
    "HttpReplicaChannel",
    "ReplicaServerPlugin",
    "create_replica_server_plugin",
    "validate_replica_config",
]
