"""Tests for config schema, validation, and loader — ported from config.test.ts."""

import json
import pytest
from pathlib import Path
from pydantic import ValidationError

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.config.validate import collect_config_warnings, validate_config
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
            encryption="delegated",
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

    def test_accepts_listable_storage_path_with_trailing_slash(self):
        # "logs/{day}/" — the last meaningful segment is the "{day}" param.
        # Parity guard with the TS validator, which now strips the trailing
        # slash before taking the last segment (as Python's rstrip already did).
        cfg = SyncConfig(
            version=1,
            collections=[
                CollectionConfig(
                    name="logs", storagePath="logs/{day}/",
                    readRoles=["cap:read:logs"], writeRoles=["cap:write:logs"],
                    encryption="none", maxBodyBytes=1024, listable=True,
                ),
            ],
        )
        assert validate_config(cfg) == []

    def test_rejects_root_only_with_public_read_role(self):
        bad = SyncConfig(
            version=1,
            collections=[
                CollectionConfig(
                    name="secret", storagePath="secret/{slot}", readRoles=["public"],
                    writeRoles=["self"], encryption="none", maxBodyBytes=1024,
                    rootOnly=True,
                ),
            ],
        )
        errors = validate_config(bad)
        assert any("rootOnly cannot be combined" in e for e in errors)

    def test_rejects_root_only_with_public_write_role(self):
        bad = SyncConfig(
            version=1,
            collections=[
                CollectionConfig(
                    name="secret", storagePath="secret/{slot}",
                    readRoles=["cap:read:secret"], writeRoles=["public"],
                    encryption="none", maxBodyBytes=1024, rootOnly=True,
                ),
            ],
        )
        errors = validate_config(bad)
        assert any("rootOnly cannot be combined" in e for e in errors)

    def test_accepts_root_only_with_non_public_roles(self):
        ok = SyncConfig(
            version=1,
            collections=[
                CollectionConfig(
                    name="secret", storagePath="secret/{slot}",
                    readRoles=["cap:read:secret"], writeRoles=["cap:write:secret"],
                    encryption="none", maxBodyBytes=1024, rootOnly=True,
                ),
            ],
        )
        assert validate_config(ok) == []


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
            "encryption": "delegated",
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


class TestValidateConfigNamespaces:
    def _ns_col(self, **kwargs) -> CollectionConfig:
        base: dict = {
            "name": "settings",
            "storagePath": "users/{identity}/settings",
            "readRoles": ["self"],
            "writeRoles": ["self"],
            "encryption": "none",
            "maxBodyBytes": 1_000_000,
        }
        base.update(kwargs)
        return CollectionConfig(**base)

    def test_valid_config_with_namespaces(self):
        from starfish_server.config.schema import NamespaceConfig
        config = SyncConfig(
            version=1, collections=[],
            namespaces={
                "tenantA": NamespaceConfig(collections=[self._ns_col()]),
                "tenantB": NamespaceConfig(collections=[self._ns_col()]),
            },
        )
        assert validate_config(config) == []

    def test_same_name_in_different_namespaces_is_valid(self):
        from starfish_server.config.schema import NamespaceConfig
        config = SyncConfig(
            version=1, collections=[],
            namespaces={
                "tenantA": NamespaceConfig(collections=[self._ns_col(name="settings")]),
                "tenantB": NamespaceConfig(collections=[self._ns_col(name="settings")]),
            },
        )
        assert validate_config(config) == []

    def test_same_name_in_root_and_namespace_is_valid(self):
        from starfish_server.config.schema import NamespaceConfig
        config = SyncConfig(
            version=1,
            collections=[self._ns_col(name="settings")],
            namespaces={"tenantA": NamespaceConfig(collections=[self._ns_col(name="settings")])},
        )
        assert validate_config(config) == []

    def test_duplicate_name_within_namespace_produces_error(self):
        from starfish_server.config.schema import NamespaceConfig
        config = SyncConfig(
            version=1, collections=[],
            namespaces={"tenantA": NamespaceConfig(collections=[self._ns_col(), self._ns_col()])},
        )
        errors = validate_config(config)
        assert len(errors) == 1
        assert 'Namespace "tenantA"' in errors[0]
        assert "Duplicate" in errors[0]

    def test_invalid_namespace_name_characters(self):
        from starfish_server.config.schema import NamespaceConfig
        config = SyncConfig(
            version=1, collections=[],
            namespaces={"bad name!": NamespaceConfig(collections=[self._ns_col()])},
        )
        errors = validate_config(config)
        assert any("letters, digits, hyphens" in e for e in errors)

    def test_reserved_namespace_names(self):
        from starfish_server.config.schema import NamespaceConfig
        for name in ("pull", "push", "list", "health", "batch"):
            config = SyncConfig(
                version=1, collections=[],
                namespaces={name: NamespaceConfig(collections=[self._ns_col()])},
            )
            errors = validate_config(config)
            assert any("reserved" in e for e in errors), f"Expected reserved error for {name!r}"

    def test_collection_errors_scoped_to_namespace(self):
        from starfish_server.config.schema import NamespaceConfig
        config = SyncConfig(
            version=1, collections=[],
            namespaces={"tenantA": NamespaceConfig(collections=[self._ns_col(storagePath="/bad")])},
        )
        errors = validate_config(config)
        assert any('Namespace "tenantA"' in e for e in errors)
        assert any("must not start with /" in e for e in errors)

    def test_hyphens_and_underscores_valid_namespace_names(self):
        from starfish_server.config.schema import NamespaceConfig
        config = SyncConfig(
            version=1, collections=[],
            namespaces={
                "tenant-a": NamespaceConfig(collections=[self._ns_col()]),
                "tenant_b": NamespaceConfig(collections=[self._ns_col()]),
            },
        )
        assert validate_config(config) == []

    def test_empty_namespace_collections_produces_error(self):
        from starfish_server.config.schema import NamespaceConfig
        config = SyncConfig(
            version=1, collections=[],
            namespaces={"tenantA": NamespaceConfig(collections=[])},
        )
        errors = validate_config(config)
        assert any("at least one collection" in e for e in errors)


class TestParseConfigJsonNamespaces:
    def test_parses_config_with_namespaces(self):
        raw = json.dumps({
            "version": 1,
            "collections": [],
            "namespaces": {
                "tenantA": {
                    "collections": [{
                        "name": "settings",
                        "storagePath": "users/{identity}/settings",
                        "readRoles": ["self"],
                        "writeRoles": ["self"],
                        "encryption": "none",
                        "maxBodyBytes": 1_000_000,
                    }]
                }
            },
        })
        config = parse_config_json(raw)
        assert config.namespaces is not None
        assert config.namespaces["tenantA"].collections[0].name == "settings"

    def test_throws_on_reserved_namespace_name(self):
        raw = json.dumps({
            "version": 1, "collections": [],
            "namespaces": {
                "push": {
                    "collections": [{
                        "name": "settings",
                        "storagePath": "users/{identity}/settings",
                        "readRoles": ["self"],
                        "writeRoles": ["self"],
                        "encryption": "none",
                        "maxBodyBytes": 1_000_000,
                    }]
                }
            },
        })
        with pytest.raises(StartupError):
            parse_config_json(raw)

    @pytest.mark.asyncio
    async def test_round_trips_namespace_config(self):
        from starfish_server.config.schema import NamespaceConfig
        from starfish_server.config.loader import save_config, load_config
        store = MemoryObjectStore()
        config = SyncConfig(
            version=1, collections=[],
            namespaces={"tenantA": NamespaceConfig(collections=[
                CollectionConfig(
                    name="settings",
                    storagePath="users/{identity}/settings",
                    readRoles=["self"],
                    writeRoles=["self"],
                    encryption="none",
                    maxBodyBytes=1_000_000,
                )
            ])},
        )
        await save_config(store, config)
        loaded = await load_config(store)
        assert loaded is not None
        assert loaded.namespaces is not None
        assert loaded.namespaces["tenantA"].collections[0].name == "settings"


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


class TestConfigWarnings:
    """Non-fatal warnings for access-widening misconfigurations."""

    def _config(self, col: CollectionConfig) -> SyncConfig:
        return SyncConfig(version=1, collections=[col])

    def test_clean_config_has_no_warnings(self):
        cfg = self._config(
            CollectionConfig(
                name="notes",
                storagePath="users/{identity}/notes",
                readRoles=["cap:read:notes"],
                writeRoles=["cap:write:notes"],
                encryption="none",
                maxBodyBytes=65536,
            )
        )
        assert collect_config_warnings(cfg) == []

    def test_warns_on_public_write_roles(self):
        cfg = self._config(
            CollectionConfig(
                name="posts",
                storagePath="posts/{id}",
                readRoles=["public"],
                writeRoles=["public"],
                encryption="none",
                maxBodyBytes=65536,
            )
        )
        warnings = collect_config_warnings(cfg)
        assert len(warnings) == 1
        assert 'writeRoles contains "public"' in warnings[0]

    def test_warns_on_cross_collection_cap_role(self):
        cfg = self._config(
            CollectionConfig(
                name="secrets",
                storagePath="users/{identity}/secrets",
                readRoles=["cap:read:notes"],  # copy-paste typo
                writeRoles=["cap:write:secrets"],
                encryption="none",
                maxBodyBytes=65536,
            )
        )
        warnings = collect_config_warnings(cfg)
        assert len(warnings) == 1
        assert 'different collection ("notes")' in warnings[0]

    def test_allows_own_cap_role_and_wildcard(self):
        cfg = self._config(
            CollectionConfig(
                name="notes",
                storagePath="users/{identity}/notes",
                readRoles=["cap:read:notes", "cap:read:*"],
                writeRoles=["cap:write:notes"],
                encryption="none",
                maxBodyBytes=65536,
            )
        )
        assert collect_config_warnings(cfg) == []

    def test_warns_on_self_role_without_identity_param(self):
        cfg = self._config(
            CollectionConfig(
                name="shared",
                storagePath="rooms/{owner}/notes",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
            )
        )
        warnings = collect_config_warnings(cfg)
        assert any('"self" role' in w and "{identity}" in w for w in warnings)

    def test_no_self_warning_with_identity_param(self):
        cfg = self._config(
            CollectionConfig(
                name="mine",
                storagePath="users/{identity}/notes",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
            )
        )
        assert collect_config_warnings(cfg) == []
