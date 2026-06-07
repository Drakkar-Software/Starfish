"""Tests for ``make_identity_role_enricher``."""

from __future__ import annotations

import pytest

from starfish_server.enrichers.identity import make_identity_role_enricher
from starfish_server.router.route_builder import AuthResult


@pytest.mark.asyncio
async def test_grants_role_on_match() -> None:
    enricher = make_identity_role_enricher("alice-id", "admin")
    roles = await enricher(AuthResult(identity="alice-id", roles=[]), {})
    assert roles == ["admin"]


@pytest.mark.asyncio
async def test_empty_on_mismatch() -> None:
    enricher = make_identity_role_enricher("alice-id", "admin")
    roles = await enricher(AuthResult(identity="bob-id", roles=[]), {})
    assert roles == []


@pytest.mark.asyncio
async def test_empty_for_anonymous_identity() -> None:
    # An empty identity must never be elevated, even if the configured id is "".
    enricher = make_identity_role_enricher("", "admin")
    roles = await enricher(AuthResult(identity="", roles=[]), {})
    assert roles == []
