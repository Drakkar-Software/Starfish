"""Tests for config schema, validation, and loader — ported from config.test.ts."""

import json
import pytest
from pathlib import Path
from pydantic import ValidationError

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.config.validate import validate_config
from starfish_server.config.loader import load_config, save_config, parse_config_json, load_config_file
from starfish_server.errors import StartupError
from tests.helpers import MemoryObjectStore

VALID_CONFIG = SyncConfig(
    version=1,
    collections=[
        CollectionConfig(
            name="signals",
            storagePath="products/{productId}/signals",
            readRoles=["public"],
            writeRoles=["owner"],
            encryption="none",
            maxBodyBytes=65536,
        ),
        CollectionConfig(
            name="settings",
            storagePath="users/{identity}/settings",
            readRoles=["self", "admin"],
            writeRoles=["self"],
            encryption="identity",
            maxBodyBytes=131072,
        ),
    ],
)


class TestSyncConfigSchema:
    def test_parses_valid_config(self):
        assert VALID_CONFIG.version == 1
        assert len(VALID_CONFIG.collections) == 2

    def test_rejects_invalid_version(self):
        with pytest.raises(ValidationError):
            SyncConfig(
                version=2,  # type: ignore[arg-type]
                collections=[],
            )

    def test_rejects_empty_collection_name(self):
        with pytest.raises(ValidationError):
            CollectionConfig(
                name="",
                storagePath="x",
                readRoles=["public"],
                writeRoles=["admin"],
                encryption="none",
                maxBodyBytes=1024,
            )


class TestValidateConfig:
    def test_returns_no_errors_for_valid_config(self):
        assert validate_config(VALID_CONFIG) == []

    def test_detects_duplicate_collection_names(self):
        dupe = SyncConfig(
            version=1,
            collections=[
                CollectionConfig(
                    name="a", storagePath="x", readRoles=["public"],
                    writeRoles=["admin"], encryption="none", maxBodyBytes=1024,
                ),
                CollectionConfig(
                    name="a", storagePath="y", readRoles=["public"],
                    writeRoles=["admin"], encryption="none", maxBodyBytes=1024,
                ),
            ],
        )
        errors = validate_config(dupe)
        assert any("Duplicate" in e for e in errors)

    def test_detects_pull_only_push_only_conflict(self):
        bad = SyncConfig(
            version=1,
            collections=[
                CollectionConfig(
                    name="a", storagePath="x", readRoles=["public"],
                    writeRoles=["admin"], encryption="none", maxBodyBytes=1024,
                    pullOnly=True, pushOnly=True,
                ),
            ],
        )
        errors = validate_config(bad)
        assert any("pullOnly" in e for e in errors)


class TestLoadSaveConfig:
    @pytest.mark.asyncio
    async def test_round_trips_config_through_storage(self):
        store = MemoryObjectStore()
        await save_config(store, VALID_CONFIG)

        loaded = await load_config(store)
        assert loaded is not None
        assert loaded.version == VALID_CONFIG.version
        assert len(loaded.collections) == len(VALID_CONFIG.collections)
        for loaded_col, orig_col in zip(loaded.collections, VALID_CONFIG.collections):
            assert loaded_col.name == orig_col.name
            assert loaded_col.storage_path == orig_col.storage_path
            assert loaded_col.encryption == orig_col.encryption

    @pytest.mark.asyncio
    async def test_returns_none_when_no_config_exists(self):
        store = MemoryObjectStore()
        loaded = await load_config(store)
        assert loaded is None


VALID_JSON = json.dumps({
    "version": 1,
    "collections": [
        {
            "name": "signals",
            "storagePath": "products/{productId}/signals",
            "readRoles": ["public"],
            "writeRoles": ["owner"],
            "encryption": "none",
            "maxBodyBytes": 65536,
        },
        {
            "name": "settings",
            "storagePath": "users/{identity}/settings",
            "readRoles": ["self", "admin"],
            "writeRoles": ["self"],
            "encryption": "identity",
            "maxBodyBytes": 131072,
        },
    ],
})


class TestParseConfigJson:
    def test_parses_valid_json_string(self):
        config = parse_config_json(VALID_JSON)
        assert config.version == 1
        assert len(config.collections) == 2
        assert config.collections[0].name == "signals"
        assert config.collections[0].storage_path == "products/{productId}/signals"

    def test_rejects_invalid_json(self):
        with pytest.raises(Exception):
            parse_config_json("not json")

    def test_rejects_semantically_invalid_config(self):
        bad = json.dumps({
            "version": 1,
            "collections": [
                {"name": "a", "storagePath": "x", "readRoles": ["public"],
                 "writeRoles": ["admin"], "encryption": "none", "maxBodyBytes": 1024,
                 "pullOnly": True, "pushOnly": True},
            ],
        })
        with pytest.raises(StartupError):
            parse_config_json(bad)


class TestLoadConfigFile:
    def test_loads_config_from_json_file(self, tmp_path: Path):
        config_file = tmp_path / "config.json"
        config_file.write_text(VALID_JSON, encoding="utf-8")

        config = load_config_file(config_file)
        assert config.version == 1
        assert len(config.collections) == 2
        assert config.collections[1].name == "settings"

    def test_loads_config_from_string_path(self, tmp_path: Path):
        config_file = tmp_path / "config.json"
        config_file.write_text(VALID_JSON, encoding="utf-8")

        config = load_config_file(str(config_file))
        assert config.version == 1

    def test_raises_on_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_config_file("/nonexistent/config.json")
