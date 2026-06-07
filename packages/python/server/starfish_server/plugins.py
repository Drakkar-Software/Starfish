"""Server plugin contract — Python mirror of plugins.ts.

Plugins are the extension mechanism for ``create_cap_cert_role_resolver``:
each plugin contributes one or more **per-kind cap-cert validators** that
run after the core signature + clock-skew + well-formedness checks.

Plugin validation is additive AND gating:

- The inline ``assert_cap_cert_well_formed`` check (run by
  ``verify_cap_cert``) is the baseline; plugins layer **additional**
  kind-specific checks on top.
- Strict-kind dispatch is **always** active (secure by default): a cap
  whose ``kind`` has no registered validator is rejected with HTTP 401.
- When ``plugins`` is omitted from ``create_cap_cert_role_resolver``, the
  built-in :data:`default_server_plugin` (device-only) is used — ``device``
  caps are accepted (the baseline suffices for an issuer proxy) but
  ``member`` caps are rejected until the app wires a validator that enforces
  the member-cap shape rules (``sharing_server_plugin``).

The baseline ``assert_cap_cert_well_formed`` only checks the generic iss/sub
userId relations — it does NOT enforce the member-cap structural barriers
(``member-self``, ``member-private-path``, ``!<col>/_keyring``, …). Those
live in ``assert_member_cap_shape`` (``starfish_sharing``) and reach the
resolver only through ``sharing_server_plugin``. Accepting ``member`` caps
without that plugin would bypass every member barrier, so the resolver
refuses them.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any, Iterable

from starfish_protocol.plugins import (
    AuthorizeContext,
    AuthorizeResult,
    CapCertValidator,
    PullHookContext,
    PullHookResult,
    PushHookContext,
    PushHookResult,
    ServerPlugin,
    WriteEvent,
)


def _noop_device_validator(_cert: Any) -> None:
    """No-op ``device`` validator.

    A device cap is a proxy for its issuer, so the baseline
    ``assert_cap_cert_well_formed`` plus the resolver's
    signature/window/nonce/revocation/scope checks fully bound it — there is
    no additional device-cap shape rule. This marker lets strict-kind
    dispatch recognize ``"device"`` as an accepted kind.
    """


default_server_plugin = ServerPlugin(
    name="default",
    cap_validators={
        "device": _noop_device_validator,
    },
)
"""Built-in **device-only** plugin — the resolver's default when no
``plugins`` are supplied.

It deliberately does NOT register ``"member"``. Member caps carry structural
barriers (``member-self``, ``member-private-path``, ``!<col>/_keyring``, …)
that live in ``assert_member_cap_shape`` (``starfish_sharing``). To accept
member caps, install ``sharing_server_plugin`` alongside this one:
``plugins=[default_server_plugin, sharing_server_plugin]``.
"""


def compose_plugin_validators(
    plugins: Iterable[ServerPlugin],
) -> dict[str, list[CapCertValidator]]:
    """Compose a list of plugins into a single ``kind → ordered validators`` map.

    Order is preserved so multiple plugins registering the same kind run
    in plugin-list order.
    """
    out: dict[str, list[CapCertValidator]] = {}
    for plugin in plugins:
        if not plugin.cap_validators:
            continue
        for kind, validator in plugin.cap_validators.items():
            if validator is None:
                continue
            out.setdefault(kind, []).append(validator)
    return out


async def dispatch_after_write(
    plugins: Iterable[ServerPlugin] | None,
    event: WriteEvent,
) -> None:
    """Dispatch *event* to every plugin's ``after_write`` hook, in plugin-list
    order.

    Each hook is awaited (sync hooks are supported too); a raise is logged and
    swallowed so one failing side effect (e.g. a queue outage) never breaks the
    client write or blocks the remaining hooks. No-op when *plugins* is falsy.
    """
    if not plugins:
        return
    for plugin in plugins:
        hook = plugin.after_write
        if hook is None:
            continue
        try:
            result = hook(event)
            if inspect.isawaitable(result):
                await result
        except Exception:
            logging.getLogger(__name__).warning(
                "after_write hook %r failed", plugin.name, exc_info=True,
            )


async def dispatch_before_pull(
    plugins: Iterable[ServerPlugin] | None,
    ctx: PullHookContext,
) -> PullHookResult:
    """Run every plugin's ``before_pull`` hook (in plugin-list order) and return
    the first non-``proceed`` directive, or ``proceed`` if all proceed.

    Used by the pull route to let an extension reject the pull (e.g. a
    write-only replica) or run a side effect first (e.g. a replica sync). A
    raise propagates — unlike ``after_write``, a ``before_pull`` failure must
    surface (it gates the read).
    """
    if not plugins:
        return PullHookResult(action="proceed")
    for plugin in plugins:
        hook = plugin.before_pull
        if hook is None:
            continue
        result = hook(ctx)
        if inspect.isawaitable(result):
            result = await result
        if result.action != "proceed":
            return result
    return PullHookResult(action="proceed")


async def dispatch_intercept_push(
    plugins: Iterable[ServerPlugin] | None,
    ctx: PushHookContext,
) -> PushHookResult:
    """Run every plugin's ``intercept_push`` hook (in plugin-list order) and
    return the first non-``proceed`` directive (``reject`` or ``respond``), or
    ``proceed`` if all proceed.

    Used by the push route to let an extension reject the push or respond on
    its behalf (e.g. proxy the write to a primary).
    """
    if not plugins:
        return PushHookResult(action="proceed")
    for plugin in plugins:
        hook = plugin.intercept_push
        if hook is None:
            continue
        result = hook(ctx)
        if inspect.isawaitable(result):
            result = await result
        if result.action != "proceed":
            return result
    return PushHookResult(action="proceed")


def has_authorize_hook(plugins: Iterable[ServerPlugin] | None) -> bool:
    """True when any plugin contributes an ``authorize`` hook.

    Lets the router skip the anonymous fast-path only when a restriction policy
    is actually wired, preserving current behavior for servers that don't use
    restrictions.
    """
    return bool(plugins) and any(p.authorize is not None for p in plugins)


async def dispatch_authorize(
    plugins: Iterable[ServerPlugin] | None,
    ctx: AuthorizeContext,
) -> AuthorizeResult:
    """Run every plugin's ``authorize`` hook (in plugin-list order) and return
    the first ``reject`` directive, or ``proceed`` if all proceed.

    Fired at the central authorization gate for every action (pull/push/list,
    incl. batch/bundle members), after roles are resolved. A raise propagates —
    like ``before_pull``, an ``authorize`` failure must surface (it gates
    access).
    """
    if not plugins:
        return AuthorizeResult(action="proceed")
    for plugin in plugins:
        hook = plugin.authorize
        if hook is None:
            continue
        result = hook(ctx)
        if inspect.isawaitable(result):
            result = await result
        if result.action != "proceed":
            return result
    return AuthorizeResult(action="proceed")


__all__ = [
    "CapCertValidator",
    "ServerPlugin",
    "WriteEvent",
    "compose_plugin_validators",
    "default_server_plugin",
    "dispatch_after_write",
    "dispatch_before_pull",
    "dispatch_intercept_push",
    "has_authorize_hook",
    "dispatch_authorize",
]
