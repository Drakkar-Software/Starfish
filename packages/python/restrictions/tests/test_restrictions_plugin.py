"""Unit tests for the restrictions plugin rule logic."""

import pytest
from starfish_protocol.plugins import AuthorizeContext
from starfish_server.config.schema import (
    CollectionConfig,
    IdentityRestriction,
    NamespaceConfig,
    SyncConfig,
)

from starfish_restrictions import (
    ROOT,
    RestrictionRule,
    RestrictionScope,
    create_restrictions_plugin,
    restrictions_from_config,
)


def ctx(
    identity: str | None = "alice",
    action: str = "pull",
    collection: str = "notes",
    namespace: str | None = None,
) -> AuthorizeContext:
    return AuthorizeContext(
        identity=identity,
        action=action,
        collection=collection,
        namespace=namespace,
        params={},
        roles=(),
    )


async def decide(rules, c):
    plugin = create_restrictions_plugin(rules=rules)
    return await plugin.authorize(c)


async def test_deny_blocks_listed_identity():
    r = await decide([RestrictionRule(mode="deny", identities=["alice"])], ctx())
    assert r.action == "reject"
    assert r.status == 403
    assert r.error == "identity restricted"


async def test_deny_allows_unlisted():
    r = await decide([RestrictionRule(mode="deny", identities=["bob"])], ctx(identity="alice"))
    assert r.action == "proceed"


async def test_deny_never_blocks_anonymous():
    r = await decide([RestrictionRule(mode="deny", identities=["alice"])], ctx(identity=None))
    assert r.action == "proceed"


async def test_allow_permits_only_listed():
    rules = [RestrictionRule(mode="allow", identities=["alice"])]
    assert (await decide(rules, ctx(identity="alice"))).action == "proceed"
    assert (await decide(rules, ctx(identity="carol"))).action == "reject"


async def test_allow_blocks_anonymous():
    r = await decide([RestrictionRule(mode="allow", identities=["alice"])], ctx(identity=None))
    assert r.action == "reject"


async def test_allow_requires_every_applicable_rule():
    rules = [
        RestrictionRule(mode="allow", identities=["alice", "bob"]),
        RestrictionRule(mode="allow", identities=["alice"], scope=RestrictionScope(collection="notes")),
    ]
    assert (await decide(rules, ctx(identity="alice"))).action == "proceed"
    assert (await decide(rules, ctx(identity="bob"))).action == "reject"


async def test_deny_beats_allow():
    rules = [
        RestrictionRule(mode="allow", identities=["alice"]),
        RestrictionRule(mode="deny", identities=["alice"], scope=RestrictionScope(action="pull")),
    ]
    assert (await decide(rules, ctx(identity="alice", action="pull"))).action == "reject"


async def test_scope_by_action():
    rules = [RestrictionRule(mode="deny", identities=["alice"], scope=RestrictionScope(action="push"))]
    assert (await decide(rules, ctx(action="push"))).action == "reject"
    assert (await decide(rules, ctx(action="pull"))).action == "proceed"


async def test_scope_by_collection():
    rules = [RestrictionRule(mode="deny", identities=["alice"], scope=RestrictionScope(collection="secret"))]
    assert (await decide(rules, ctx(collection="secret"))).action == "reject"
    assert (await decide(rules, ctx(collection="notes"))).action == "proceed"


async def test_scope_by_namespace_and_root():
    ns_rules = [RestrictionRule(mode="deny", identities=["alice"], scope=RestrictionScope(namespace="acme"))]
    assert (await decide(ns_rules, ctx(namespace="acme"))).action == "reject"
    assert (await decide(ns_rules, ctx(namespace=None))).action == "proceed"

    root_rules = [RestrictionRule(mode="deny", identities=["alice"], scope=RestrictionScope(namespace=ROOT))]
    assert (await decide(root_rules, ctx(namespace=None))).action == "reject"
    assert (await decide(root_rules, ctx(namespace="acme"))).action == "proceed"


async def test_sync_callback_identities():
    rules = [
        RestrictionRule(
            mode="deny",
            identities=lambda c: ["alice"] if c.collection == "notes" else [],
        )
    ]
    assert (await decide(rules, ctx(collection="notes"))).action == "reject"
    assert (await decide(rules, ctx(collection="other"))).action == "proceed"


async def test_async_callback_identities():
    async def banned(_c):
        return ["alice"]

    rules = [RestrictionRule(mode="deny", identities=banned)]
    assert (await decide(rules, ctx())).action == "reject"


def _config() -> SyncConfig:
    return SyncConfig(
        version=1,
        restrictions=[IdentityRestriction(mode="deny", identities=["server-bad"])],
        collections=[
            CollectionConfig(
                name="notes",
                storagePath="notes/{identity}",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=1024,
                restrictions=[
                    IdentityRestriction(mode="deny", identities=["notes-bad"], actions=["push"])
                ],
            ),
        ],
        namespaces={
            "acme": NamespaceConfig(
                restrictions=[IdentityRestriction(mode="allow", identities=["acme-user"])],
                collections=[
                    CollectionConfig(
                        name="settings",
                        storagePath="settings/{identity}",
                        readRoles=["self"],
                        writeRoles=["self"],
                        encryption="none",
                        maxBodyBytes=1024,
                    ),
                ],
            ),
        },
    )


def test_restrictions_from_config_compiles_all_levels():
    rules = restrictions_from_config(_config())
    # server-wide deny (no scope)
    assert any(r.mode == "deny" and list(r.identities) == ["server-bad"] and r.scope.namespace is None and r.scope.collection is None and r.scope.action is None for r in rules)
    # collection push-only deny under root
    assert any(
        r.mode == "deny"
        and list(r.identities) == ["notes-bad"]
        and r.scope.namespace == ROOT
        and r.scope.collection == "notes"
        and r.scope.action == "push"
        for r in rules
    )
    # namespace-level allow
    assert any(
        r.mode == "allow" and list(r.identities) == ["acme-user"] and r.scope.namespace == "acme"
        for r in rules
    )


async def test_config_rules_enforced_through_plugin():
    plugin = create_restrictions_plugin(config=_config())
    assert (await plugin.authorize(ctx(identity="server-bad", collection="notes"))).action == "reject"
    assert (await plugin.authorize(ctx(identity="notes-bad", collection="notes", action="push"))).action == "reject"
    assert (await plugin.authorize(ctx(identity="notes-bad", collection="notes", action="pull"))).action == "proceed"


async def test_root_collection_rule_isolated_from_same_named_namespace_collection():
    cfg = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="notes",
                storagePath="notes/{identity}",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=1024,
                restrictions=[IdentityRestriction(mode="deny", identities=["alice"])],
            ),
        ],
        namespaces={
            "acme": NamespaceConfig(
                collections=[
                    CollectionConfig(
                        name="notes",
                        storagePath="notes/{identity}",
                        readRoles=["self"],
                        writeRoles=["self"],
                        encryption="none",
                        maxBodyBytes=1024,
                    ),
                ],
            ),
        },
    )
    plugin = create_restrictions_plugin(config=cfg)
    # root notes → denied; acme/notes (same name) → not denied
    assert (await plugin.authorize(ctx(identity="alice", collection="notes", namespace=None))).action == "reject"
    assert (await plugin.authorize(ctx(identity="alice", collection="notes", namespace="acme"))).action == "proceed"


def test_namespace_collection_level_restriction_compiles():
    cfg = SyncConfig(
        version=1,
        collections=[],
        namespaces={
            "acme": NamespaceConfig(
                collections=[
                    CollectionConfig(
                        name="settings",
                        storagePath="settings/{identity}",
                        readRoles=["self"],
                        writeRoles=["self"],
                        encryption="none",
                        maxBodyBytes=1024,
                        restrictions=[IdentityRestriction(mode="deny", identities=["ns-col-bad"])],
                    ),
                ],
            ),
        },
    )
    rules = restrictions_from_config(cfg)
    assert any(
        r.mode == "deny"
        and list(r.identities) == ["ns-col-bad"]
        and r.scope.namespace == "acme"
        and r.scope.collection == "settings"
        and r.scope.action is None
        for r in rules
    )
