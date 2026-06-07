"""Identity action restrictions plugin for Starfish.

Builds a :class:`ServerPlugin` whose ``authorize`` hook denies access by
identity, scoped to the whole server, a namespace, a collection, or a single
action. Mirrors ``@drakkar.software/starfish-restrictions`` (TypeScript).
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Awaitable, Callable, Literal, Sequence

from starfish_protocol.plugins import (
    AuthorizeContext,
    AuthorizeResult,
    ServerPlugin,
)
from starfish_server.config.schema import IdentityRestriction, SyncConfig

RestrictionAction = Literal["pull", "push", "list"]

#: Source of identities for a rule: a static list, or a callable invoked per
#: request with the :class:`AuthorizeContext`. The callable may be async.
IdentitySource = (
    Sequence[str]
    | Callable[[AuthorizeContext], Sequence[str]]
    | Callable[[AuthorizeContext], Awaitable[Sequence[str]]]
)


@dataclass
class RestrictionScope:
    """Narrows which requests a :class:`RestrictionRule` applies to.

    An unset field matches everything; an empty scope makes the rule
    server-wide. ``namespace`` may be the sentinel ``ROOT`` to target the
    un-namespaced (root) collections specifically.
    """

    namespace: str | None = None
    """Target namespace. ``None`` (default) matches any namespace; use the
    :data:`ROOT` sentinel to target the root collections specifically."""

    collection: str | None = None
    """Target collection name. ``None`` matches any collection."""

    action: RestrictionAction | None = None
    """Target action. ``None`` matches any action."""


#: Sentinel for :attr:`RestrictionScope.namespace` meaning "the root
#: (un-namespaced) collections", as distinct from ``None`` ("any namespace").
ROOT = "\0root\0"


@dataclass
class RestrictionRule:
    """One restriction rule.

    ``mode="deny"`` blocks the listed identities; ``mode="allow"`` permits ONLY
    the listed identities (everyone else, including anonymous callers, is
    blocked) for the rule's scope. When multiple rules apply, **deny wins**, and
    the caller must satisfy *every* applicable allow rule.
    """

    mode: Literal["deny", "allow"]
    identities: IdentitySource
    scope: RestrictionScope | None = None


def restrictions_from_config(config: SyncConfig) -> list[RestrictionRule]:
    """Compile the static ``restrictions`` declared throughout a
    :class:`SyncConfig` into :class:`RestrictionRule` objects.

    A server-level restriction becomes a server-wide rule; a namespace-level one
    is scoped to that namespace; a collection-level one is scoped to that
    collection (and its namespace, if any). A restriction listing ``actions``
    expands to one rule per action.
    """
    rules: list[RestrictionRule] = []

    def expand(restriction: IdentityRestriction, base: RestrictionScope) -> None:
        actions: list[RestrictionAction | None] = list(restriction.actions or []) or [None]
        for action in actions:
            scope = RestrictionScope(
                namespace=base.namespace,
                collection=base.collection,
                action=action,
            )
            rules.append(
                RestrictionRule(
                    mode=restriction.mode,
                    identities=list(restriction.identities),
                    scope=scope,
                )
            )

    for r in config.restrictions or []:
        expand(r, RestrictionScope())

    for col in config.collections:
        for r in col.restrictions or []:
            expand(r, RestrictionScope(namespace=ROOT, collection=col.name))

    for ns_name, ns in (config.namespaces or {}).items():
        for r in ns.restrictions or []:
            expand(r, RestrictionScope(namespace=ns_name))
        for col in ns.collections:
            for r in col.restrictions or []:
                expand(r, RestrictionScope(namespace=ns_name, collection=col.name))

    return rules


def _rule_applies(rule: RestrictionRule, ctx: AuthorizeContext) -> bool:
    s = rule.scope
    if s is None:
        return True
    if s.action is not None and s.action != ctx.action:
        return False
    if s.collection is not None and s.collection != ctx.collection:
        return False
    if s.namespace is not None:
        # ROOT targets the un-namespaced collections (ctx.namespace is None);
        # any other string targets that namespace by name.
        want = None if s.namespace == ROOT else s.namespace
        if want != ctx.namespace:
            return False
    return True


async def _resolve_identities(source: IdentitySource, ctx: AuthorizeContext) -> Sequence[str]:
    if callable(source):
        result = source(ctx)
        if inspect.isawaitable(result):
            result = await result
        return result
    return source


def create_restrictions_plugin(
    rules: Sequence[RestrictionRule] | None = None,
    config: SyncConfig | None = None,
    status: int = 403,
    error: str = "identity restricted",
) -> ServerPlugin:
    """Build a :class:`ServerPlugin` that denies access by identity.

    Install it alongside your other plugins in ``SyncRouterOptions.plugins``::

        create_sync_router(SyncRouterOptions(
            store=store, config=config, role_resolver=role_resolver,
            plugins=[
                default_server_plugin,
                create_restrictions_plugin(
                    config=config,  # enforce static `restrictions` from the config
                    rules=[
                        RestrictionRule(mode="deny", identities=["evil-user"]),
                        RestrictionRule(
                            mode="deny",
                            identities=lambda ctx: load_banned(ctx.collection),
                            scope=RestrictionScope(collection="notes", action="push"),
                        ),
                    ],
                ),
            ],
        ))

    Evaluation: **deny wins** — if any applicable ``deny`` rule lists the caller,
    the request is rejected. Otherwise the caller must be listed in *every*
    applicable ``allow`` rule.
    """
    all_rules: list[RestrictionRule] = []
    if config is not None:
        all_rules.extend(restrictions_from_config(config))
    if rules:
        all_rules.extend(rules)

    reject = AuthorizeResult(action="reject", status=status, error=error)
    proceed = AuthorizeResult(action="proceed")

    async def authorize(ctx: AuthorizeContext) -> AuthorizeResult:
        identity = ctx.identity
        for rule in all_rules:
            if not _rule_applies(rule, ctx):
                continue
            listed = await _resolve_identities(rule.identities, ctx)
            if rule.mode == "deny":
                if identity is not None and identity in listed:
                    return reject
            else:  # allow: only listed identities pass; anonymous never matches
                if identity is None or identity not in listed:
                    return reject
        return proceed

    return ServerPlugin(name="restrictions", authorize=authorize)
