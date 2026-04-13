"""Semantic validation beyond what Pydantic covers."""


import re

from starfish_server.config.schema import SyncConfig, WriteMode, CollectionConfig
from starfish_server.constants import ENCRYPTION_IDENTITY, ENCRYPTION_SERVER, ENCRYPTION_DELEGATED, IDENTITY_PARAM, ROLE_PUBLIC

MIME_JSON = "application/json"

_NS_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
_RESERVED_NS_NAMES = frozenset({"pull", "push", "health", "batch"})


def _is_binary_collection(allowed_mime_types: list[str]) -> bool:
    return MIME_JSON not in [m.lower() for m in allowed_mime_types]


def _validate_collections(collections: list[CollectionConfig], scope_label: str) -> list[str]:
    """Validate a list of collections and return error messages.

    *scope_label* is prepended to errors so callers can distinguish root
    errors from namespace errors (e.g. ``'Namespace "tenantA": '``).
    """
    errors: list[str] = []
    names: set[str] = set()
    prefix = f"{scope_label}: " if scope_label else ""

    for col in collections:
        # Duplicate names within this scope
        if col.name in names:
            errors.append(f'{prefix}Duplicate collection name: "{col.name}"')
        names.add(col.name)

        # storagePath must not start with /
        if col.storage_path.startswith("/"):
            errors.append(f'{prefix}Collection "{col.name}": storagePath must not start with /')

        # pullOnly + pushOnly conflict
        if col.pull_only and col.push_only:
            errors.append(f'{prefix}Collection "{col.name}": cannot be both pullOnly and pushOnly')

        # queueOnly cannot be used with binary collections (no JSON hash for raw bytes)
        if col.queue_only and _is_binary_collection(col.allowed_mime_types):
            errors.append(f'{prefix}Collection "{col.name}": queueOnly cannot be used with binary collections')

        # queueOnly + pullOnly: push is disabled so queueOnly has no effect
        if col.queue_only and col.pull_only:
            errors.append(f'{prefix}Collection "{col.name}": queueOnly cannot be used with pullOnly (push routes are disabled)')

        # queueOnly + remote: nothing stored locally, replication has nothing to read
        if col.queue_only and col.remote:
            errors.append(f'{prefix}Collection "{col.name}": queueOnly cannot be used with remote replication (no data is stored locally to replicate)')

        if col.listable:
            param_matches = re.findall(r"\{[^}]+\}", col.storage_path)
            if not param_matches:
                errors.append(
                    f'{prefix}Collection "{col.name}": listable requires at least one path parameter in storagePath'
                )
            else:
                last_segment = col.storage_path.rstrip("/").split("/")[-1]
                if not re.fullmatch(r"\{[^}]+\}", last_segment):
                    errors.append(
                        f'{prefix}Collection "{col.name}": listable requires the last storagePath segment '
                        f'to be a path parameter (e.g. {{day}}), got "{last_segment}"'
                    )
            if col.queue_only:
                errors.append(
                    f'{prefix}Collection "{col.name}": listable cannot be used with queueOnly (no documents are stored)'
                )
            if col.bundle:
                errors.append(
                    f'{prefix}Collection "{col.name}": listable cannot be used with bundle (bundled collections share storage paths)'
                )

        # Public collections must not use identity-based encryption
        if ROLE_PUBLIC in col.read_roles and col.encryption == ENCRYPTION_IDENTITY:
            errors.append(
                f'{prefix}Collection "{col.name}": public collections must not use '
                f'"{ENCRYPTION_IDENTITY}" encryption (key would be derived from empty identity)'
            )

        # Bundled collections must use identity encryption
        if col.bundle and col.encryption != ENCRYPTION_IDENTITY:
            errors.append(
                f'{prefix}Collection "{col.name}": bundled collections must use "{ENCRYPTION_IDENTITY}" encryption'
            )

        # Bundled collections must have {identity} in storagePath
        if col.bundle and IDENTITY_PARAM not in col.storage_path:
            errors.append(
                f'{prefix}Collection "{col.name}": bundled collections must have {IDENTITY_PARAM} in storagePath'
            )

        # readRoles should not be empty (unless pullOnly)
        if not col.pull_only and not col.read_roles:
            errors.append(
                f'{prefix}Collection "{col.name}": readRoles must not be empty (use ["{ROLE_PUBLIC}"] for public access)'
            )

        # Binary collection constraints (allowedMimeTypes without application/json)
        is_binary = _is_binary_collection(col.allowed_mime_types)
        if is_binary:
            if col.encryption in (ENCRYPTION_IDENTITY, ENCRYPTION_SERVER):
                errors.append(
                    f'{prefix}Collection "{col.name}": binary collections cannot use '
                    f'"{col.encryption}" encryption (storage layer is string-based)'
                )
            if col.object_schema is not None:
                errors.append(
                    f'{prefix}Collection "{col.name}": binary collections cannot have objectSchema'
                )
            if col.bundle:
                errors.append(
                    f'{prefix}Collection "{col.name}": binary collections cannot be part of a bundle'
                )
            if col.remote:
                errors.append(
                    f'{prefix}Collection "{col.name}": binary collections cannot have remote replication'
                )
        if not col.allowed_mime_types:
            errors.append(
                f'{prefix}Collection "{col.name}": allowedMimeTypes must contain at least one pattern'
            )

        # Remote collection constraints
        if col.remote:
            # storagePath must be static — template variables cannot be resolved for replication
            if re.search(r"\{[^}]+\}", col.storage_path):
                errors.append(
                    f'{prefix}Collection "{col.name}": remote collections must have a static storagePath '
                    f'with no template variables (found "{col.storage_path}")'
                )
            # pushOnly conflicts with replication (replica writes locally)
            if col.push_only:
                errors.append(f'{prefix}Collection "{col.name}": remote collections cannot be pushOnly')
            # Bundle support would require coordinating multiple document keys
            if col.bundle:
                errors.append(f'{prefix}Collection "{col.name}": remote collections cannot be part of a bundle')
            # Delegated encryption is opaque to the server — cannot replicate client-encrypted blobs
            if col.encryption == ENCRYPTION_DELEGATED:
                errors.append(
                    f'{prefix}Collection "{col.name}": remote collections cannot use delegated encryption '
                    f'(server cannot replicate opaque client-encrypted blobs)'
                )
            # push_through and bidirectional require a push_path to forward writes to the primary
            if col.remote.write_mode in (WriteMode.PUSH_THROUGH, WriteMode.BIDIRECTIONAL):
                if not col.remote.push_path:
                    errors.append(
                        f'{prefix}Collection "{col.name}": write_mode "{col.remote.write_mode.value}" '
                        f'requires remote.push_path to be set'
                    )

    # Check bundles: all collections in same bundle must share storagePath
    bundles: dict[str, str] = {}
    for col in collections:
        if not col.bundle:
            continue
        existing = bundles.get(col.bundle)
        if existing and existing != col.storage_path:
            errors.append(
                f'{prefix}Bundle "{col.bundle}": all collections must share the same storagePath '
                f'(found "{existing}" and "{col.storage_path}")'
            )
        bundles[col.bundle] = col.storage_path

    return errors


def validate_config(config: SyncConfig) -> list[str]:
    """Validate config semantics. Returns error messages (empty = valid)."""
    errors = _validate_collections(config.collections, "")

    if config.namespaces:
        for ns_name, ns_config in config.namespaces.items():
            # Namespace name format: only letters, digits, hyphens, underscores
            if not _NS_NAME_RE.match(ns_name):
                errors.append(
                    f'Namespace "{ns_name}": name must contain only letters, digits, hyphens, '
                    f'and underscores (got "{ns_name}")'
                )

            # Reserved names that would collide with root routes
            if ns_name in _RESERVED_NS_NAMES:
                errors.append(
                    f'Namespace "{ns_name}": name is reserved and cannot be used as a namespace'
                )

            # Each namespace must have at least one collection
            if not ns_config.collections:
                errors.append(
                    f'Namespace "{ns_name}": must contain at least one collection'
                )

            # Validate collections within this namespace scope
            errors.extend(_validate_collections(ns_config.collections, f'Namespace "{ns_name}"'))

    return errors
