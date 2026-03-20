"""Semantic validation beyond what Pydantic covers."""


import re

from starfish_server.config.schema import SyncConfig, SyncTrigger, WriteMode
from starfish_server.constants import ENCRYPTION_IDENTITY, ENCRYPTION_SERVER, ENCRYPTION_DELEGATED, IDENTITY_PARAM, ROLE_PUBLIC

MIME_JSON = "application/json"


def _is_binary_collection(allowed_mime_types: list[str]) -> bool:
    return MIME_JSON not in [m.lower() for m in allowed_mime_types]


def validate_config(config: SyncConfig) -> list[str]:
    """Validate config semantics. Returns error messages (empty = valid)."""
    errors: list[str] = []
    names: set[str] = set()

    for col in config.collections:
        # Duplicate names
        if col.name in names:
            errors.append(f'Duplicate collection name: "{col.name}"')
        names.add(col.name)

        # storagePath must not start with /
        if col.storage_path.startswith("/"):
            errors.append(f'Collection "{col.name}": storagePath must not start with /')

        # pullOnly + pushOnly conflict
        if col.pull_only and col.push_only:
            errors.append(f'Collection "{col.name}": cannot be both pullOnly and pushOnly')

        # Public collections must not use identity-based encryption
        if ROLE_PUBLIC in col.read_roles and col.encryption == ENCRYPTION_IDENTITY:
            errors.append(
                f'Collection "{col.name}": public collections must not use '
                f'"{ENCRYPTION_IDENTITY}" encryption (key would be derived from empty identity)'
            )

        # Bundled collections must use identity encryption
        if col.bundle and col.encryption != ENCRYPTION_IDENTITY:
            errors.append(
                f'Collection "{col.name}": bundled collections must use "{ENCRYPTION_IDENTITY}" encryption'
            )

        # Bundled collections must have {identity} in storagePath
        if col.bundle and IDENTITY_PARAM not in col.storage_path:
            errors.append(
                f'Collection "{col.name}": bundled collections must have {IDENTITY_PARAM} in storagePath'
            )

        # readRoles should not be empty (unless pullOnly)
        if not col.pull_only and not col.read_roles:
            errors.append(
                f'Collection "{col.name}": readRoles must not be empty (use ["{ROLE_PUBLIC}"] for public access)'
            )

        # Binary collection constraints (allowedMimeTypes without application/json)
        is_binary = _is_binary_collection(col.allowed_mime_types)
        if is_binary:
            if col.encryption in (ENCRYPTION_IDENTITY, ENCRYPTION_SERVER):
                errors.append(
                    f'Collection "{col.name}": binary collections cannot use '
                    f'"{col.encryption}" encryption (storage layer is string-based)'
                )
            if col.object_schema is not None:
                errors.append(
                    f'Collection "{col.name}": binary collections cannot have objectSchema'
                )
            if col.bundle:
                errors.append(
                    f'Collection "{col.name}": binary collections cannot be part of a bundle'
                )
            if col.remote:
                errors.append(
                    f'Collection "{col.name}": binary collections cannot have remote replication'
                )
        if not col.allowed_mime_types:
            errors.append(
                f'Collection "{col.name}": allowedMimeTypes must contain at least one pattern'
            )

        # Remote collection constraints
        if col.remote:
            # storagePath must be static — template variables cannot be resolved for replication
            if re.search(r"\{[^}]+\}", col.storage_path):
                errors.append(
                    f'Collection "{col.name}": remote collections must have a static storagePath '
                    f'with no template variables (found "{col.storage_path}")'
                )
            # pushOnly conflicts with replication (replica writes locally)
            if col.push_only:
                errors.append(f'Collection "{col.name}": remote collections cannot be pushOnly')
            # Bundle support would require coordinating multiple document keys
            if col.bundle:
                errors.append(f'Collection "{col.name}": remote collections cannot be part of a bundle')
            # Delegated encryption is opaque to the server — cannot replicate client-encrypted blobs
            if col.encryption == ENCRYPTION_DELEGATED:
                errors.append(
                    f'Collection "{col.name}": remote collections cannot use delegated encryption '
                    f'(server cannot replicate opaque client-encrypted blobs)'
                )
            # push_through and bidirectional require a push_path to forward writes to the primary
            if col.remote.write_mode in (WriteMode.PUSH_THROUGH, WriteMode.BIDIRECTIONAL):
                if not col.remote.push_path:
                    errors.append(
                        f'Collection "{col.name}": write_mode "{col.remote.write_mode.value}" '
                        f'requires remote.push_path to be set'
                    )
            # webhook trigger requires a shared secret for HMAC verification
            if SyncTrigger.WEBHOOK in col.remote.sync_triggers and not col.remote.webhook_secret:
                errors.append(
                    f'Collection "{col.name}": sync trigger "webhook" requires remote.webhook_secret to be set'
                )

    # Check bundles: all collections in same bundle must share storagePath
    bundles: dict[str, str] = {}
    for col in config.collections:
        if not col.bundle:
            continue
        existing = bundles.get(col.bundle)
        if existing and existing != col.storage_path:
            errors.append(
                f'Bundle "{col.bundle}": all collections must share the same storagePath '
                f'(found "{existing}" and "{col.storage_path}")'
            )
        bundles[col.bundle] = col.storage_path

    return errors
