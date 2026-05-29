"""Plugin contract types — shared by the server host and extension packages.

The ``ServerPlugin`` dataclass and ``CapCertValidator`` alias live in the
protocol package (the shared contract layer) so that ``starfish-server``
(the host) and the extension packages (``starfish-identities``,
``starfish-sharing``) can both reference them without a dependency cycle.

The runtime helpers that consume the contract — ``compose_plugin_validators``
and ``default_server_plugin`` — live in ``starfish_server.plugins``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Literal, Mapping


CapCertValidator = Callable[[Any], None]
"""Validator for a specific cap-cert ``kind``.

Raises on failure; the server's cap-resolver translates the raise into
HTTP 401 with the thrown message. Validators run **after** the core
``verify_cap_cert`` checks (signature, nbf/exp window, baseline
well-formedness).
"""


@dataclass
class WriteEvent:
    """Payload handed to a plugin's ``after_write`` hook after a successful
    push (HTTP 200). Side-effect extensions (queue publishing, audit,
    webhooks, change-data-capture) consume it without the server knowing
    their concern."""

    collection: str
    """Collection name the write targeted."""

    hash: str
    """Content hash of the stored document, as returned to the client."""

    timestamp: int
    """Server timestamp of the write, as returned to the client."""

    params: Mapping[str, str]
    """Route path parameters (e.g. ``{"user_id": "..."}``)."""

    body: Mapping[str, Any] | None = None
    """The pushed ``data`` object, when the collection is JSON and the
    request body parsed to a plain object. Hooks decide whether to use it."""

    namespace: str | None = None
    """Namespace name when the write went through a named sub-router."""

    identity: str | None = None
    """The authenticated writer identity (``auth.identity``): the cap-bound
    userId of the account that performed the write (``iss_user_id`` for a device
    cap, ``sub_user_id`` for a member cap, the presenter's derived userId for an
    audience cap). ``None`` for an unauthenticated (public) write. Hooks that
    forward this off-box (e.g. queue publishing) MUST gate it behind explicit
    config, since it exposes *who* wrote — metadata the server otherwise never
    emits."""


AfterWriteHook = Callable[["WriteEvent"], "Awaitable[None] | None"]
"""Hook invoked once per registered plugin after a successful push. Runs in
plugin-list order. Failures are logged by the server, never propagated — a
hook outage must not break client writes."""


@dataclass
class PullHookContext:
    """Context handed to a plugin's ``before_pull`` hook, before the local store
    is read for a pull. Framework-neutral (no FastAPI types) so the contract
    stays host-agnostic — mirrors :class:`WriteEvent`."""

    collection: str
    """Collection name being pulled."""

    params: Mapping[str, str]
    """Resolved route path parameters."""

    namespace: str | None = None
    """Namespace name when the pull went through a named sub-router."""


@dataclass
class PushHookContext:
    """Context handed to a plugin's ``intercept_push`` hook, before a push is
    written locally. Carries the already-read raw request body so a hook can
    forward it upstream (e.g. proxy the write to a primary)."""

    collection: str
    """Collection name being pushed to."""

    params: Mapping[str, str]
    """Resolved route path parameters."""

    raw_body: str
    """Raw request body as received from the client."""

    namespace: str | None = None
    """Namespace name when the push went through a named sub-router."""


@dataclass
class PullHookResult:
    """Directive a ``before_pull`` hook returns. ``proceed`` lets the pull
    continue; ``reject`` short-circuits with an HTTP error."""

    action: Literal["proceed", "reject"]
    status: int | None = None
    error: str | None = None


@dataclass
class PushHookResult:
    """Directive an ``intercept_push`` hook returns. ``proceed`` lets the local
    write continue; ``reject`` short-circuits with an HTTP error; ``respond``
    short-circuits with a full response body (e.g. a push proxied to a
    primary)."""

    action: Literal["proceed", "reject", "respond"]
    status: int | None = None
    error: str | None = None
    body: Any | None = None


BeforePullHook = Callable[["PullHookContext"], "PullHookResult | Awaitable[PullHookResult]"]
"""Hook invoked before a pull is served. Hosts call it for every pulled
collection; plugins filter by ``ctx.collection``. Runs in plugin-list order;
the first ``reject`` wins."""

InterceptPushHook = Callable[["PushHookContext"], "PushHookResult | Awaitable[PushHookResult]"]
"""Hook invoked before a push is written locally. Hosts call it for every
pushed collection; plugins filter by ``ctx.collection``. Runs in plugin-list
order; the first non-``proceed`` result wins."""


@dataclass
class ServerPlugin:
    """Plugin contributing per-kind cap-cert validators and/or write-path
    side-effect hooks to the server.

    Apps compose the behaviors they want by listing each extension's plugin.
    """

    name: str
    """Human-readable name. Used in error messages and audit logs."""

    cap_validators: Mapping[str, CapCertValidator] = field(default_factory=dict)
    """Per-kind validators. The resolver dispatches by ``cert["kind"]`` to
    validators that registered that kind. Multiple plugins may register the
    same kind — they run in plugin-list order; any raise rejects the
    request."""

    after_write: AfterWriteHook | None = None
    """Invoked after each successful push (HTTP 200). Additive — plugins that
    only validate caps leave it ``None``. See :class:`WriteEvent`."""

    before_pull: "BeforePullHook | None" = None
    """Invoked before a pull is served, before the local store is read. Lets an
    extension short-circuit the pull or run a side effect first (e.g. a replica
    syncing from its primary). Additive. See :class:`PullHookContext`."""

    intercept_push: "InterceptPushHook | None" = None
    """Invoked before a push is written locally. Lets an extension reject the
    push or respond on its behalf (e.g. proxy the write to a primary).
    Additive. See :class:`PushHookContext`."""

    shutdown: Callable[[], "Awaitable[None] | None"] | None = None
    """Invoked during graceful shutdown so the plugin can release resources
    (e.g. close a queue connection). Additive."""


__all__ = [
    "CapCertValidator",
    "ServerPlugin",
    "WriteEvent",
    "AfterWriteHook",
    "PullHookContext",
    "PushHookContext",
    "PullHookResult",
    "PushHookResult",
    "BeforePullHook",
    "InterceptPushHook",
]
