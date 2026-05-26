"""Semantic validation beyond what Pydantic covers."""


import re

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.constants import ROLE_PUBLIC, ROLE_SELF

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

        if col.append_only:
            persist = col.append_only.persist
            if col.append_only.type != "by_timestamp":
                errors.append(
                    f'{prefix}Collection "{col.name}": appendOnly.type "{col.append_only.type}" '
                    f'is not supported (expected "by_timestamp")'
                )
            if _is_binary_collection(col.allowed_mime_types):
                errors.append(f'{prefix}Collection "{col.name}": appendOnly cannot be used with binary collections')
            if col.pull_only:
                errors.append(f'{prefix}Collection "{col.name}": appendOnly cannot be used with pullOnly (push routes are disabled)')
            if persist:
                # persist=True (default) — the stored-array path. ``delegated``
                # encryption is now supported: each element's ``data`` is stored
                # opaquely, so the server never reads ciphertext to append (only
                # the plaintext per-element ``ts`` envelope).
                if col.bundle:
                    errors.append(
                        f'{prefix}Collection "{col.name}": appendOnly with persist=true cannot be used with bundle'
                    )

            def _is_pos_int(n: int | None) -> bool:
                return n is None or (isinstance(n, int) and not isinstance(n, bool) and n > 0)

            if not _is_pos_int(col.append_only.max_items):
                errors.append(f'{prefix}Collection "{col.name}": appendOnly.maxItems must be a positive integer')
            if not _is_pos_int(col.append_only.chunk_size):
                errors.append(f'{prefix}Collection "{col.name}": appendOnly.chunkSize must be a positive integer')
            if persist is False:
                if col.append_only.max_items is not None:
                    errors.append(
                        f'{prefix}Collection "{col.name}": appendOnly.maxItems requires persist=true (nothing is stored when persist=false)'
                    )
                if col.append_only.chunk_size is not None:
                    errors.append(
                        f'{prefix}Collection "{col.name}": appendOnly.chunkSize requires persist=true (nothing is stored when persist=false)'
                    )

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
            if col.append_only and col.append_only.persist is False:
                errors.append(
                    f'{prefix}Collection "{col.name}": listable cannot be used with appendOnly+persist=false (no documents are stored)'
                )
            if col.bundle:
                errors.append(
                    f'{prefix}Collection "{col.name}": listable cannot be used with bundle (bundled collections share storage paths)'
                )

        # rootOnly is incompatible with public access — a root-only collection
        # can never be public.
        if col.root_only and (
            ROLE_PUBLIC in col.read_roles or ROLE_PUBLIC in col.write_roles
        ):
            errors.append(
                f'{prefix}Collection "{col.name}": rootOnly cannot be combined with '
                f'the "{ROLE_PUBLIC}" role in readRoles/writeRoles (a root-only '
                f"collection is never public)"
            )

        # readRoles should not be empty (unless pullOnly)
        if not col.pull_only and not col.read_roles:
            errors.append(
                f'{prefix}Collection "{col.name}": readRoles must not be empty (use ["{ROLE_PUBLIC}"] for public access)'
            )

        # Binary collection constraints (allowedMimeTypes without application/json)
        is_binary = _is_binary_collection(col.allowed_mime_types)
        if is_binary:
            if col.object_schema is not None:
                errors.append(
                    f'{prefix}Collection "{col.name}": binary collections cannot have objectSchema'
                )
            if col.bundle:
                errors.append(
                    f'{prefix}Collection "{col.name}": binary collections cannot be part of a bundle'
                )
        if not col.allowed_mime_types:
            errors.append(
                f'{prefix}Collection "{col.name}": allowedMimeTypes must contain at least one pattern'
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


_CAP_ROLE_RE = re.compile(r"^cap:(read|write|list):(.+)$")


def _collect_collection_warnings(
    collections: list[CollectionConfig], scope_label: str
) -> list[str]:
    """Non-fatal checks for likely access-widening misconfigurations.

    - A ``public`` entry in ``write_roles`` lets *anonymous* clients write.
    - A ``cap:<op>:<other>`` role naming a DIFFERENT collection is almost always
      a copy-paste typo that grants cross-collection access (the cap-resolver
      synthesizes ``cap:<op>:<collection>`` per the cert's scope).
    """
    warnings: list[str] = []
    prefix = f"{scope_label}: " if scope_label else ""
    for col in collections:
        if ROLE_PUBLIC in (col.write_roles or []):
            warnings.append(
                f'{prefix}Collection "{col.name}": writeRoles contains "{ROLE_PUBLIC}" — '
                "anonymous clients can WRITE this collection. Remove it unless public "
                "writes are intended."
            )

        def _check_cross(roles: list[str] | None, label: str) -> None:
            for r in roles or []:
                m = _CAP_ROLE_RE.fullmatch(r)
                if m and m.group(2) != col.name and m.group(2) != "*":
                    warnings.append(
                        f'{prefix}Collection "{col.name}": {label} references "{r}", a cap '
                        f'role scoped to a different collection ("{m.group(2)}"). A cap-cert '
                        f'for "{m.group(2)}" would gain access here — did you mean '
                        f'"cap:{m.group(1)}:{col.name}"?'
                    )

        _check_cross(col.read_roles, "readRoles")
        _check_cross(col.write_roles, "writeRoles")

        # The "self" role is granted only when the "{identity}" path param
        # equals the caller. A collection that uses "self" but whose storage_path
        # has no "{identity}" segment (e.g. it used "{owner}"/"{userId}") will
        # NEVER be granted "self" — likely a typo where per-user isolation was
        # intended.
        uses_self = ROLE_SELF in (col.read_roles or []) or ROLE_SELF in (col.write_roles or [])
        if uses_self and "{identity}" not in col.storage_path:
            warnings.append(
                f'{prefix}Collection "{col.name}": uses the "{ROLE_SELF}" role but its '
                'storagePath has no "{identity}" segment. "'
                f'{ROLE_SELF}" is granted only when the "{{identity}}" path param equals '
                "the caller, so it can never be granted here — did you mean to use "
                '"{identity}" instead of another param name?'
            )
    return warnings


def collect_config_warnings(config: SyncConfig) -> list[str]:
    """Collect non-fatal config warnings (see :func:`_collect_collection_warnings`).

    Returns an empty list for a clean config. Surfaced at load time by the
    config loader; also exported so apps can lint configs themselves.
    """
    warnings = _collect_collection_warnings(config.collections, "")
    if config.namespaces:
        for ns_name, ns_config in config.namespaces.items():
            warnings.extend(
                _collect_collection_warnings(ns_config.collections, f'Namespace "{ns_name}"')
            )
    return warnings


def validate_config(config: SyncConfig) -> list[str]:
    """Validate config semantics. Returns error messages (empty = valid)."""
    errors = _validate_collections(config.collections, "")

    if config.namespaces:
        for ns_name, ns_config in config.namespaces.items():
            # Namespace name format: only letters, digits, hyphens, underscores
            if not _NS_NAME_RE.fullmatch(ns_name):
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
