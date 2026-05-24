"""Tests for replica config validation (validate_replica_config)."""


from starfish_server.config.schema import CollectionConfig, SyncConfig

from starfish_replica.config import RemoteConfig, WriteMode
from starfish_replica.validate import validate_replica_config


def _col(**kwargs) -> CollectionConfig:
    """Build a minimal collection config, overriding with kwargs."""
    defaults = dict(
        name="featured",
        storagePath="posts/featured",
        readRoles=["public"],
        writeRoles=[],
        encryption="none",
        maxBodyBytes=65536,
        pullOnly=True,
    )
    defaults.update(kwargs)
    return CollectionConfig(**defaults)


def _config(*cols: CollectionConfig) -> SyncConfig:
    return SyncConfig(version=1, collections=list(cols))


def _remote(**kwargs) -> RemoteConfig:
    defaults = dict(
        url="https://primary.example.com/v1",
        pullPath="/pull/posts/featured",
        intervalMs=30_000,
    )
    defaults.update(kwargs)
    return RemoteConfig(**defaults)


def test_valid_remote_collection_passes():
    errors = validate_replica_config(_config(_col()), {"featured": _remote()})
    assert errors == []


def test_remote_for_unknown_collection_rejected():
    errors = validate_replica_config(_config(_col()), {"ghost": _remote()})
    assert any("unknown root collection" in e for e in errors)


def test_remote_with_template_vars_rejected():
    col = _col(storagePath="users/{identity}/data")
    errors = validate_replica_config(_config(col), {"featured": _remote()})
    assert any("template variables" in e for e in errors)


def test_remote_push_only_rejected():
    col = _col(pushOnly=True, pullOnly=None)
    errors = validate_replica_config(_config(col), {"featured": _remote()})
    assert any("pushOnly" in e for e in errors)


def test_remote_in_bundle_rejected():
    col = _col(storagePath="users/shared/data", bundle="my-bundle")
    errors = validate_replica_config(_config(col), {"featured": _remote()})
    assert any("bundle" in e for e in errors)


def test_remote_delegated_encryption_rejected():
    col = _col(encryption="delegated")
    errors = validate_replica_config(_config(col), {"featured": _remote()})
    assert any("delegated" in e for e in errors)


def test_appendonly_remote_rejected():
    col = _col(appendOnly=True)
    errors = validate_replica_config(_config(col), {"featured": _remote()})
    assert any("appendOnly cannot be used with remote replication" in e for e in errors)


def test_binary_remote_rejected():
    col = _col(allowedMimeTypes=["image/png"])
    errors = validate_replica_config(_config(col), {"featured": _remote()})
    assert any("binary collections cannot have remote replication" in e for e in errors)


def test_push_through_without_push_path_rejected():
    errors = validate_replica_config(
        _config(_col()), {"featured": _remote(writeMode=WriteMode.PUSH_THROUGH)}
    )
    assert any("push_path" in e for e in errors)


def test_bidirectional_without_push_path_rejected():
    errors = validate_replica_config(
        _config(_col()), {"featured": _remote(writeMode=WriteMode.BIDIRECTIONAL)}
    )
    assert any("push_path" in e for e in errors)


def test_push_through_with_push_path_passes():
    errors = validate_replica_config(
        _config(_col(pullOnly=None)),
        {"featured": _remote(pushPath="/push/posts/featured", writeMode=WriteMode.PUSH_THROUGH)},
    )
    assert errors == []


def test_push_only_without_push_path_passes():
    """PUSH_ONLY does not require push_path (writes are local-only, no proxying)."""
    errors = validate_replica_config(
        _config(_col(pullOnly=None)),
        {"featured": _remote(writeMode=WriteMode.PUSH_ONLY)},
    )
    assert errors == []
