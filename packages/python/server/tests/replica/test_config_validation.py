"""Tests for remote collection config validation."""


import pytest

from starfish_server.config.schema import (
    CollectionConfig,
    RemoteConfig,
    SyncConfig,
    SyncTrigger,
    WriteMode,
)
from starfish_server.config.validate import validate_config


def _remote_col(**kwargs) -> CollectionConfig:
    """Build a minimal valid remote collection config, overriding with kwargs."""
    defaults = dict(
        name="featured",
        storagePath="posts/featured",
        readRoles=["public"],
        writeRoles=[],
        encryption="none",
        maxBodyBytes=65536,
        pullOnly=True,
        remote=RemoteConfig(
            url="https://primary.example.com/v1",
            pullPath="/pull/posts/featured",
            intervalMs=30_000,
        ),
    )
    defaults.update(kwargs)
    return CollectionConfig(**defaults)


def _config(*cols: CollectionConfig) -> SyncConfig:
    return SyncConfig(version=1, collections=list(cols))


def test_valid_remote_collection_passes():
    errors = validate_config(_config(_remote_col()))
    assert errors == []


def test_remote_with_template_vars_rejected():
    col = _remote_col(storagePath="users/{identity}/data")
    errors = validate_config(_config(col))
    assert any("template variables" in e for e in errors)


def test_remote_push_only_rejected():
    col = _remote_col(pushOnly=True, pullOnly=None)
    errors = validate_config(_config(col))
    assert any("pushOnly" in e for e in errors)


def test_remote_in_bundle_rejected():
    col = _remote_col(
        storagePath="users/shared/data",
        bundle="my-bundle",
        encryption="none",
        readRoles=["public"],
    )
    # Note: bundle validation also fires because bundle requires identity encryption,
    # but we also want the "cannot be part of a bundle" error
    errors = validate_config(_config(col))
    assert any("bundle" in e for e in errors)


def test_remote_delegated_encryption_rejected():
    col = _remote_col(encryption="delegated")
    errors = validate_config(_config(col))
    assert any("delegated" in e for e in errors)


def test_push_through_without_push_path_rejected():
    col = _remote_col(
        remote=RemoteConfig(
            url="https://primary.example.com/v1",
            pullPath="/pull/posts/featured",
            writeMode=WriteMode.PUSH_THROUGH,
            # push_path intentionally omitted
        )
    )
    errors = validate_config(_config(col))
    assert any("push_path" in e for e in errors)


def test_bidirectional_without_push_path_rejected():
    col = _remote_col(
        remote=RemoteConfig(
            url="https://primary.example.com/v1",
            pullPath="/pull/posts/featured",
            writeMode=WriteMode.BIDIRECTIONAL,
        )
    )
    errors = validate_config(_config(col))
    assert any("push_path" in e for e in errors)


def test_webhook_trigger_without_secret_rejected():
    col = _remote_col(
        remote=RemoteConfig(
            url="https://primary.example.com/v1",
            pullPath="/pull/posts/featured",
            syncTriggers=[SyncTrigger.WEBHOOK],
            # webhook_secret intentionally omitted
        )
    )
    errors = validate_config(_config(col))
    assert any("webhook_secret" in e for e in errors)


def test_webhook_trigger_with_secret_passes():
    col = _remote_col(
        remote=RemoteConfig(
            url="https://primary.example.com/v1",
            pullPath="/pull/posts/featured",
            syncTriggers=[SyncTrigger.WEBHOOK],
            webhookSecret="supersecret",
        )
    )
    errors = validate_config(_config(col))
    assert errors == []


def test_push_through_with_push_path_passes():
    col = _remote_col(
        pullOnly=None,
        remote=RemoteConfig(
            url="https://primary.example.com/v1",
            pullPath="/pull/posts/featured",
            pushPath="/push/posts/featured",
            writeMode=WriteMode.PUSH_THROUGH,
        ),
    )
    errors = validate_config(_config(col))
    assert errors == []


def test_push_only_without_push_path_passes():
    """PUSH_ONLY does not require push_path (writes are local-only, no proxying)."""
    col = _remote_col(
        pullOnly=None,
        remote=RemoteConfig(
            url="https://primary.example.com/v1",
            pullPath="/pull/posts/featured",
            writeMode=WriteMode.PUSH_ONLY,
        ),
    )
    errors = validate_config(_config(col))
    assert errors == []
