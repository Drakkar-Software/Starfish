"""``starfish_replica.space`` — mirror a local data source into a Starfish space.

A second :class:`~starfish_replica.channel.ReplicaChannel` implementation
alongside the HTTP one: instead of pulling a primary server's document into a
local ``ObjectStore``, it pushes an app-local projection into per-collection
nodes of one or more Starfish spaces.

Requires ``starfish-spaces`` — declared as the ``space`` optional extra
(``pip install starfish-replica[space]``). ``port.py`` is the only module here
that imports it.

Mirrors the TS package's ``./space`` subpath export.

## Not implemented: the read side

This subpackage is write-only. The TS subpath additionally exports
``readSpaceMirror`` — a session-less reader that, given a member cap for the
space plus ephemeral keys, pulls and decrypts every node it recognizes.

That is a gap rather than a design position. It has not been written because
it needs a part of ``starfish_spaces`` a writer never exercises:
invite/link-cap resolution and per-node keyrings (``get_node_access`` tiers 1
and 3), which the Python package covers less completely than the TS one.
A reader means filling that in first.

## Scheduling

``ReplicaManager`` re-exported here IS
:class:`~starfish_replica.scheduler.ChannelScheduler` — the same class, under
the name the TS subpath uses. It has no ``starfish_server`` dependency of its
own; note that unlike TS (where ``./space`` is a separate bundle entry),
importing this subpackage still evaluates ``starfish_replica/__init__.py``,
and ``starfish-server`` is a hard dependency of the distribution in both
languages regardless.
"""

from starfish_replica.channel import (
    REPLICATOR_CTX,
    ChannelSchedule,
    ReplicaCallContext,
    ReplicaChannel,
    ScheduledChannel,
)
from starfish_replica.scheduler import ChannelScheduler
from starfish_replica.scheduler import ChannelScheduler as ReplicaManager
from starfish_replica.space.mirror_channel import (
    DEFAULT_NODE_ENC,
    SpaceMirrorChannel,
    SpaceMirrorCollection,
    SpaceMirrorResult,
    create_space_mirror_channel,
)
from starfish_replica.space.plan import (
    ExistingSpaceNode,
    SpaceMirrorPlan,
    plan_space_mirror,
)
from starfish_replica.space.port import (
    NodeAccessHandle,
    SpacePort,
    default_space_port,
    find_or_create_space,
    flatten_object_tree,
)

__all__ = [
    # channel seam
    "ReplicaChannel",
    "ReplicaCallContext",
    "REPLICATOR_CTX",
    "ChannelSchedule",
    "ScheduledChannel",
    "ChannelScheduler",
    "ReplicaManager",
    # mirror channel
    "SpaceMirrorChannel",
    "SpaceMirrorCollection",
    "SpaceMirrorResult",
    "create_space_mirror_channel",
    "DEFAULT_NODE_ENC",
    # plan
    "ExistingSpaceNode",
    "SpaceMirrorPlan",
    "plan_space_mirror",
    # port
    "SpacePort",
    "NodeAccessHandle",
    "default_space_port",
    "find_or_create_space",
    "flatten_object_tree",
]
