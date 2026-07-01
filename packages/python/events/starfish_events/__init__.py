"""``starfish-events`` — Starfish server plugin (Python) that intercepts JSON
event-batch pushes from the SunGlasses adapter and encodes them as Parquet
files on S3.

Python mirror of ``@drakkar.software/starfish-events`` (``packages/ts/events``).

Public surface
--------------
- :func:`create_events_server_plugin` — factory that returns a
  :class:`~starfish_protocol.plugins.ServerPlugin` whose ``intercept_push``
  hook encodes event batches as Parquet.
- :func:`encode_parquet` — low-level encoder (exposed for testing and direct
  use).
- :func:`generate_sortable_batch_id` — the server-assigned, lexicographically-
  sortable id the plugin uses for each stored batch (exposed for testing and
  direct use).
- :data:`COLUMNS` — the fixed 10-column tuple that forms the Parquet schema.
"""

from starfish_events.encode import COLUMNS, encode_parquet
from starfish_events.sortable_id import generate_sortable_batch_id


def __getattr__(name: str):
    """Lazy import of :func:`create_events_server_plugin`.

    Keeps ``starfish_server`` off the hot path for callers that only import the
    types or the encoder — mirrors the pattern used in ``starfish_projection``.
    """
    if name == "create_events_server_plugin":
        from starfish_events.plugin import create_events_server_plugin as _f

        return _f
    raise AttributeError(f"module 'starfish_events' has no attribute {name!r}")


__all__ = [
    "COLUMNS",
    "encode_parquet",
    "generate_sortable_batch_id",
    "create_events_server_plugin",
]
