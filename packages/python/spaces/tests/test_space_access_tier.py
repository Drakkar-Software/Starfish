"""Security regression: a plaintext node must never be handed an encryptor.

## The hazard this pins

``get_node_access`` resolves through six tiers, and every tier that can return
builds an encryptor whenever one can be derived. Tier 5 (owner self-mint) falls
back to the SPACE keyring — which exists in any space holding at least one
``enc=True`` node, because ``create_node`` minted it there.

So before the ``node=`` argument existed, a node declared
``access:"public", enc:False`` was handed an encryptor anyway. A caller that
seals on ``handle.encryptor is not None`` — which is exactly what
``starfish_replica``'s ``push_node_doc`` does — would then write
``{"_encrypted": ...}`` into a collection the server declares
``encryption="none"``: ``objpub``, whose ``read_roles`` are ``["public"]``. The
push succeeds with 200, nothing errors at any layer, and the world reads an
opaque blob forever.

## What these tests do and do not cover

They exercise the TIER GUARD, not keyring cryptography. Tier 5's encryptor
builders are replaced with a sentinel so "an encryptor was resolved" is
deterministic and observable; whether real keyring material would decrypt is
covered by the keyring package's own tests. That separation is deliberate — it
is what lets ``test_the_guard_is_not_vacuous`` prove these assertions would
actually fail without the fix.

Contrast ``test_space_owner_access.py``, whose fake client raises on every pull
and so forces both of Tier 5's encryptor attempts to ``None``. It cannot observe
this bug: it passes identically with or without the fix.
"""

from __future__ import annotations

import pytest

import starfish_spaces.node_keyring as node_keyring_module
import starfish_spaces.space_access as space_access_module
from starfish_spaces.space_access import (
    build_node_access,
    clear_node_access_cache,
    get_node_access,
)

from .helpers import make_fake_session

SENTINEL_ENCRYPTOR = object()


class MemoryClient:
    """Absent documents pull as an EMPTY doc, not a 404 — matching the real server."""

    def __init__(self) -> None:
        self.docs: dict[str, dict] = {}

    class _Res:
        def __init__(self, data, hash_):
            self.data = data
            self.hash = hash_

    async def pull(self, path):
        return self._Res(self.docs.get(path, {}), None)

    async def push(self, path, payload, base_hash=None):
        self.docs[path] = payload


@pytest.fixture
def owner_session(monkeypatch):
    """An owner session whose Tier-5 encryptor resolution ALWAYS succeeds.

    This is the precondition that makes the hazard reachable: in a real mixed
    space the keyring exists (the private collections minted it), so Tier 5
    genuinely returns an encryptor. Forcing that here means any encryptor
    observed below came from Tier 5 and any absence came from the guard.
    """

    async def always_resolves(*_args, **_kwargs):
        return SENTINEL_ENCRYPTOR

    # Tier 5 tries the per-node keyring first, then falls back to the space one.
    # Both are stubbed so the test does not depend on which path wins.
    monkeypatch.setattr(node_keyring_module, "build_node_encryptor", always_resolves)
    monkeypatch.setattr(space_access_module, "build_encryptor", always_resolves)

    client = MemoryClient()
    session = make_fake_session(account_client=client, content_client=client)
    session.node_id_prefix = "nd_"
    session.space_id_prefix = "sp_"
    return session


@pytest.fixture(autouse=True)
def _clean_cache():
    clear_node_access_cache()
    space_access_module._space_encryptor_cache.clear()
    yield
    clear_node_access_cache()
    space_access_module._space_encryptor_cache.clear()


# ── the guard is not vacuous ─────────────────────────────────────────────────


async def test_the_guard_is_not_vacuous(owner_session):
    """Proves these assertions would FAIL without the fix.

    Omitting ``node`` leaves the resolver unable to know the tier, so it runs
    Tier 5 and returns the sentinel. That is precisely the pre-fix behaviour for
    a public node — and it is what every assertion below rules out.
    """
    handle = await get_node_access(owner_session, "sp-1", "nd-unknown-tier")

    assert handle.encryptor is SENTINEL_ENCRYPTOR


# ── the regression ───────────────────────────────────────────────────────────


async def test_a_public_node_is_never_handed_an_encryptor(owner_session):
    handle = await get_node_access(
        owner_session, "sp-1", "nd-public", {"access": "public", "enc": False}
    )

    assert handle.encryptor is None


async def test_a_node_with_enc_absent_is_treated_as_plaintext(owner_session):
    # create_node stores `enc=True if enc else None`, so a plaintext node carries
    # no `enc` key at all. A `is False` check would miss this; `not .get("enc")`
    # catches it. This is the shape create_node actually writes.
    handle = await get_node_access(owner_session, "sp-1", "nd-public", {"access": "public"})

    assert handle.encryptor is None


async def test_a_public_node_still_gets_a_usable_client(owner_session):
    # Suppressing the encryptor must not suppress the write path.
    handle = await get_node_access(
        owner_session, "sp-1", "nd-public", {"access": "public", "enc": False}
    )

    assert handle.client is not None


async def test_an_encrypted_node_in_the_same_space_still_seals(owner_session):
    # The control. A guard that simply disabled encryption everywhere would pass
    # every other test in this file; this is what stops that.
    public = await get_node_access(
        owner_session, "sp-1", "nd-a", {"access": "public", "enc": False}
    )
    private = await get_node_access(
        owner_session, "sp-1", "nd-b", {"access": "space", "enc": True}
    )

    assert public.encryptor is None
    assert private.encryptor is SENTINEL_ENCRYPTOR


async def test_an_invite_plaintext_node_is_also_unsealed(owner_session):
    # `access:"invite", enc:false` is a legal combination (objinv) and is just as
    # plaintext as public. The guard keys off enc, not off access.
    handle = await get_node_access(
        owner_session, "sp-1", "nd-invite", {"access": "invite", "enc": False}
    )

    assert handle.encryptor is None


async def test_build_node_access_honours_the_same_guard(owner_session):
    # The soft variant is a separate entry point and would otherwise be a hole.
    handle = await build_node_access(
        owner_session, "sp-1", "nd-public", {"access": "public", "enc": False}
    )

    assert handle.encryptor is None


# ── caching ──────────────────────────────────────────────────────────────────


async def test_the_cache_does_not_leak_an_encryptor_across_tiers(owner_session):
    """The cache key includes the tier. Without it, resolving the ENCRYPTED view of
    a node first would poison the plaintext view with its encryptor — the same
    ciphertext-into-objpub failure, reached via the cache instead of the resolver."""
    encrypted = await get_node_access(
        owner_session, "sp-1", "nd-x", {"access": "space", "enc": True}
    )
    plaintext = await get_node_access(
        owner_session, "sp-1", "nd-x", {"access": "public", "enc": False}
    )

    assert encrypted.encryptor is SENTINEL_ENCRYPTOR
    assert plaintext.encryptor is None
    assert encrypted is not plaintext


async def test_the_cache_leak_is_blocked_in_both_orders(owner_session):
    # Resolving plaintext first must not deny the encrypted view its encryptor.
    plaintext = await get_node_access(
        owner_session, "sp-1", "nd-y", {"access": "public", "enc": False}
    )
    encrypted = await get_node_access(
        owner_session, "sp-1", "nd-y", {"access": "space", "enc": True}
    )

    assert plaintext.encryptor is None
    assert encrypted.encryptor is SENTINEL_ENCRYPTOR


async def test_repeated_resolution_of_the_same_tier_is_cached(owner_session):
    first = await get_node_access(
        owner_session, "sp-1", "nd-z", {"access": "public", "enc": False}
    )
    second = await get_node_access(
        owner_session, "sp-1", "nd-z", {"access": "public", "enc": False}
    )

    assert first is second


async def test_different_nodes_do_not_share_a_handle(owner_session):
    a = await get_node_access(owner_session, "sp-1", "nd-1", {"access": "public"})
    b = await get_node_access(owner_session, "sp-1", "nd-2", {"access": "public"})

    assert a is not b
