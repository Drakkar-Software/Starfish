"""Replica config validation.

Cross-references the ``remotes`` map (collection name → :class:`RemoteConfig`)
against the server's :class:`SyncConfig` collections. These rules were
previously inline in ``starfish-server``'s config validator; they moved here
when the ``remote`` field left the core ``CollectionConfig``.
"""

from __future__ import annotations

import re

from starfish_server.config.schema import CollectionConfig, SyncConfig
from starfish_server.constants import ENCRYPTION_DELEGATED

from starfish_replica.config import RemoteConfig, WriteMode

MIME_JSON = "application/json"


def _is_binary_collection(allowed_mime_types: list[str]) -> bool:
    return MIME_JSON not in [m.lower() for m in allowed_mime_types]


def validate_replica_config(
    config: SyncConfig,
    remotes: dict[str, RemoteConfig],
) -> list[str]:
    """Validate the replica configuration. Returns error messages (empty = valid)."""
    errors: list[str] = []
    by_name: dict[str, CollectionConfig] = {c.name: c for c in config.collections}

    for name, remote in remotes.items():
        col = by_name.get(name)
        if col is None:
            errors.append(
                f'Collection "{name}": remote replication configured for an unknown root collection'
            )
            continue

        if col.append_only:
            errors.append(f'Collection "{name}": appendOnly cannot be used with remote replication')
        if _is_binary_collection(col.allowed_mime_types):
            errors.append(f'Collection "{name}": binary collections cannot have remote replication')
        if re.search(r"\{[^}]+\}", col.storage_path):
            errors.append(
                f'Collection "{name}": remote collections must have a static storagePath '
                f'with no template variables (found "{col.storage_path}")'
            )
        if col.push_only:
            errors.append(f'Collection "{name}": remote collections cannot be pushOnly')
        if col.bundle:
            errors.append(f'Collection "{name}": remote collections cannot be part of a bundle')
        if col.encryption == ENCRYPTION_DELEGATED:
            errors.append(
                f'Collection "{name}": remote collections cannot use "{col.encryption}" encryption '
                f'(server cannot replicate opaque client-encrypted blobs)'
            )
        if remote.write_mode in (WriteMode.PUSH_THROUGH, WriteMode.BIDIRECTIONAL):
            if not remote.push_path:
                errors.append(
                    f'Collection "{name}": write_mode "{remote.write_mode.value}" '
                    f'requires remote.push_path to be set'
                )

    return errors
