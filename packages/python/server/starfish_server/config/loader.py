"""Load and save sync configuration from/to object storage or JSON."""


import json
from pathlib import Path

from starfish_server.storage.base import AbstractObjectStore
from starfish_server.config.schema import SyncConfig
from starfish_server.config.validate import validate_config
from starfish_server.errors import StartupError
from starfish_server.constants import DEFAULT_CONFIG_KEY, CONTENT_TYPE_JSON


def parse_config_json(raw: str) -> SyncConfig:
    """Parse and validate a SyncConfig from a JSON string.

    Accepts camelCase keys (e.g. ``storagePath``) as used in JSON config files.

    Raises :class:`StartupError` if semantic validation fails.
    """
    parsed = SyncConfig.model_validate_json(raw)
    errors = validate_config(parsed)
    if errors:
        raise StartupError(f"Invalid sync config:\n" + "\n".join(errors))
    return parsed


def load_config_file(path: str | Path) -> SyncConfig:
    """Load and validate a SyncConfig from a JSON file on disk.

    Raises :class:`FileNotFoundError` if the file does not exist, or
    :class:`StartupError` if validation fails.
    """
    return parse_config_json(Path(path).read_text(encoding="utf-8"))


async def load_config(
    store: AbstractObjectStore,
    config_key: str = DEFAULT_CONFIG_KEY,
) -> SyncConfig | None:
    """Load and validate a SyncConfig from storage.

    Returns None if no config exists at the given key.
    """
    raw = await store.get_string(config_key)
    if raw is None:
        return None

    parsed = SyncConfig.model_validate_json(raw)
    errors = validate_config(parsed)
    if errors:
        raise StartupError(f"Invalid sync config:\n" + "\n".join(errors))
    return parsed


async def save_config(
    store: AbstractObjectStore,
    config: SyncConfig,
    config_key: str = DEFAULT_CONFIG_KEY,
) -> None:
    """Save a SyncConfig to storage. Validates before saving."""
    errors = validate_config(config)
    if errors:
        raise StartupError(f"Invalid sync config:\n" + "\n".join(errors))

    await store.put(
        config_key,
        config.model_dump_json(by_alias=True, indent=2),
        content_type=CONTENT_TYPE_JSON,
    )
