"""Tests for TTL / document expiration."""

import time
from starfish_server.ttl import is_expired


def test_not_expired_when_timestamp_zero():
    assert is_expired(0, 60_000) is False


def test_not_expired_for_recent_document():
    assert is_expired(time.time() * 1000 - 1000, 60_000) is False


def test_expired_for_old_document():
    assert is_expired(time.time() * 1000 - 120_000, 60_000) is True
