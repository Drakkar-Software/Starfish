"""Tests for TTL / document expiration."""

import time
from starfish_server.ttl import is_expired


def test_not_expired_when_timestamp_zero():
    assert is_expired(0, 60_000) is False


def test_not_expired_for_recent_document():
    assert is_expired(time.time() * 1000 - 1000, 60_000) is False


def test_expired_for_old_document():
    assert is_expired(time.time() * 1000 - 120_000, 60_000) is True


def test_never_expires_when_ttl_zero():
    now_ms = time.time() * 1000
    assert is_expired(now_ms - 999_999_999, 0) is False


def test_never_expires_when_ttl_negative():
    now_ms = time.time() * 1000
    assert is_expired(now_ms - 999_999_999, -1) is False


def test_never_expires_when_ttl_none():
    now_ms = time.time() * 1000
    assert is_expired(now_ms - 999_999_999, None) is False


def test_expired_strictly_greater_than_ttl():
    now_ms = time.time() * 1000
    assert is_expired(now_ms - 60_001, 60_000) is True
