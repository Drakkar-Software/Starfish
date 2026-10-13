"""Dispatcher contract for the server plugin hooks in ``starfish_server.plugins``.

The restrictions and router suites exercise these hooks end to end. These tests
pin the dispatcher rules those suites do not isolate: plugin-list ordering,
first-directive-wins short-circuiting, fail-closed propagation for gating hooks
(``authorize``, ``before_pull``) and log-and-continue for ``after_write``.
"""

from __future__ import annotations

import logging

import pytest

from starfish_protocol.plugins import (
    AuthorizeContext,
    AuthorizeResult,
    InterceptPullResult,
    PullHookContext,
    PullHookResult,
    PushHookContext,
    PushHookResult,
    WriteEvent,
)
from starfish_server.plugins import (
    ServerPlugin,
    dispatch_after_write,
    dispatch_authorize,
    dispatch_before_pull,
    dispatch_intercept_pull,
    dispatch_intercept_push,
    has_authorize_hook,
)


def _auth_ctx(**overrides) -> AuthorizeContext:
    fields = {"action": "pull", "collection": "notes", "params": {}}
    fields.update(overrides)
    return AuthorizeContext(**fields)


def _pull_ctx() -> PullHookContext:
    return PullHookContext(collection="notes", params={})


def _push_ctx() -> PushHookContext:
    return PushHookContext(collection="notes", params={}, raw_body="{}")


def _write_event() -> WriteEvent:
    return WriteEvent(collection="notes", hash="h1", timestamp=1, params={})


def _proceed_authorize(_ctx: AuthorizeContext) -> AuthorizeResult:
    return AuthorizeResult(action="proceed")


class TestHasAuthorizeHook:
    def test_none_and_empty_have_no_hook(self) -> None:
        assert has_authorize_hook(None) is False
        assert has_authorize_hook([]) is False

    def test_plugin_without_authorize_has_no_hook(self) -> None:
        assert has_authorize_hook([ServerPlugin(name="plain")]) is False

    def test_any_plugin_with_authorize_enables_hook(self) -> None:
        plugins = [ServerPlugin(name="plain"), ServerPlugin(name="gate", authorize=_proceed_authorize)]
        assert has_authorize_hook(plugins) is True


class TestDispatchAuthorize:
    async def test_no_plugins_proceeds(self) -> None:
        assert (await dispatch_authorize(None, _auth_ctx())).action == "proceed"
        assert (await dispatch_authorize([], _auth_ctx())).action == "proceed"

    async def test_plugins_without_authorize_are_skipped(self) -> None:
        result = await dispatch_authorize([ServerPlugin(name="plain")], _auth_ctx())
        assert result.action == "proceed"

    async def test_first_reject_wins_and_later_hooks_do_not_run(self) -> None:
        calls: list[str] = []

        def deny(_ctx: AuthorizeContext) -> AuthorizeResult:
            calls.append("deny")
            return AuthorizeResult(action="reject", status=403, error="blocked")

        def later(_ctx: AuthorizeContext) -> AuthorizeResult:
            calls.append("later")
            return AuthorizeResult(action="proceed")

        plugins = [ServerPlugin(name="a", authorize=deny), ServerPlugin(name="b", authorize=later)]
        result = await dispatch_authorize(plugins, _auth_ctx())

        assert result.action == "reject"
        assert result.status == 403
        assert result.error == "blocked"
        assert calls == ["deny"]

    async def test_all_proceed_returns_proceed(self) -> None:
        plugins = [
            ServerPlugin(name="a", authorize=_proceed_authorize),
            ServerPlugin(name="b", authorize=_proceed_authorize),
        ]
        assert (await dispatch_authorize(plugins, _auth_ctx())).action == "proceed"

    async def test_async_hook_is_awaited(self) -> None:
        async def deny(_ctx: AuthorizeContext) -> AuthorizeResult:
            return AuthorizeResult(action="reject", status=403)

        result = await dispatch_authorize([ServerPlugin(name="a", authorize=deny)], _auth_ctx())
        assert result.action == "reject"

    async def test_hook_exception_propagates_so_access_fails_closed(self) -> None:
        def broken(_ctx: AuthorizeContext) -> AuthorizeResult:
            raise RuntimeError("policy store unavailable")

        plugins = [ServerPlugin(name="a", authorize=broken)]
        with pytest.raises(RuntimeError, match="policy store unavailable"):
            await dispatch_authorize(plugins, _auth_ctx())

    async def test_exception_in_later_hook_still_propagates_after_proceed(self) -> None:
        def broken(_ctx: AuthorizeContext) -> AuthorizeResult:
            raise RuntimeError("boom")

        plugins = [
            ServerPlugin(name="a", authorize=_proceed_authorize),
            ServerPlugin(name="b", authorize=broken),
        ]
        with pytest.raises(RuntimeError, match="boom"):
            await dispatch_authorize(plugins, _auth_ctx())

    async def test_context_fields_reach_the_hook(self) -> None:
        seen: dict[str, object] = {}

        def capture(ctx: AuthorizeContext) -> AuthorizeResult:
            seen.update(
                action=ctx.action,
                collection=ctx.collection,
                params=dict(ctx.params),
                identity=ctx.identity,
                namespace=ctx.namespace,
                roles=ctx.roles,
            )
            return AuthorizeResult(action="proceed")

        ctx = _auth_ctx(
            action="push",
            collection="docs",
            params={"id": "42"},
            identity="alice",
            namespace="team",
            roles=("editor",),
        )
        await dispatch_authorize([ServerPlugin(name="a", authorize=capture)], ctx)

        assert seen == {
            "action": "push",
            "collection": "docs",
            "params": {"id": "42"},
            "identity": "alice",
            "namespace": "team",
            "roles": ("editor",),
        }


class TestDispatchBeforePull:
    async def test_no_plugins_proceeds(self) -> None:
        assert (await dispatch_before_pull(None, _pull_ctx())).action == "proceed"
        assert (await dispatch_before_pull([], _pull_ctx())).action == "proceed"

    async def test_first_reject_short_circuits(self) -> None:
        calls: list[str] = []

        def reject(_ctx: PullHookContext) -> PullHookResult:
            calls.append("reject")
            return PullHookResult(action="reject", status=409, error="replica is write-only")

        def later(_ctx: PullHookContext) -> PullHookResult:
            calls.append("later")
            return PullHookResult(action="proceed")

        plugins = [ServerPlugin(name="a", before_pull=reject), ServerPlugin(name="b", before_pull=later)]
        result = await dispatch_before_pull(plugins, _pull_ctx())

        assert result.action == "reject"
        assert result.status == 409
        assert calls == ["reject"]

    async def test_async_hook_is_awaited(self) -> None:
        async def reject(_ctx: PullHookContext) -> PullHookResult:
            return PullHookResult(action="reject", status=503)

        result = await dispatch_before_pull([ServerPlugin(name="a", before_pull=reject)], _pull_ctx())
        assert result.status == 503

    async def test_hook_exception_propagates_because_it_gates_the_read(self) -> None:
        def broken(_ctx: PullHookContext) -> PullHookResult:
            raise RuntimeError("sync failed")

        with pytest.raises(RuntimeError, match="sync failed"):
            await dispatch_before_pull([ServerPlugin(name="a", before_pull=broken)], _pull_ctx())


class TestDispatchAfterWrite:
    async def test_no_plugins_is_a_noop(self) -> None:
        await dispatch_after_write(None, _write_event())
        await dispatch_after_write([], _write_event())

    async def test_sync_and_async_hooks_run_in_plugin_order(self) -> None:
        order: list[str] = []

        def first(_event: WriteEvent) -> None:
            order.append("sync")

        async def second(_event: WriteEvent) -> None:
            order.append("async")

        plugins = [
            ServerPlugin(name="a", after_write=first),
            ServerPlugin(name="skipped"),
            ServerPlugin(name="b", after_write=second),
        ]
        await dispatch_after_write(plugins, _write_event())

        assert order == ["sync", "async"]

    async def test_failing_hook_is_logged_and_remaining_hooks_still_run(self, caplog) -> None:
        calls: list[str] = []

        def broken(_event: WriteEvent) -> None:
            calls.append("broken")
            raise RuntimeError("queue outage")

        def healthy(_event: WriteEvent) -> None:
            calls.append("healthy")

        plugins = [
            ServerPlugin(name="broken", after_write=broken),
            ServerPlugin(name="healthy", after_write=healthy),
        ]
        with caplog.at_level(logging.WARNING, logger="starfish_server.plugins"):
            await dispatch_after_write(plugins, _write_event())

        assert calls == ["broken", "healthy"]
        assert any("broken" in rec.getMessage() and rec.exc_info for rec in caplog.records)


class TestDispatchInterceptPush:
    async def test_no_plugins_proceeds(self) -> None:
        assert (await dispatch_intercept_push(None, _push_ctx())).action == "proceed"

    async def test_first_respond_wins_over_later_hooks(self) -> None:
        calls: list[str] = []

        def respond(_ctx: PushHookContext) -> PushHookResult:
            calls.append("respond")
            return PushHookResult(action="respond", status=202, body={"proxied": True})

        def later(_ctx: PushHookContext) -> PushHookResult:
            calls.append("later")
            return PushHookResult(action="reject", status=403)

        plugins = [
            ServerPlugin(name="a", intercept_push=respond),
            ServerPlugin(name="b", intercept_push=later),
        ]
        result = await dispatch_intercept_push(plugins, _push_ctx())

        assert result.action == "respond"
        assert result.body == {"proxied": True}
        assert calls == ["respond"]

    async def test_proceed_falls_through_to_next_hook(self) -> None:
        plugins = [
            ServerPlugin(name="a", intercept_push=lambda _ctx: PushHookResult(action="proceed")),
            ServerPlugin(name="b", intercept_push=lambda _ctx: PushHookResult(action="reject", status=422)),
        ]
        result = await dispatch_intercept_push(plugins, _push_ctx())
        assert result.action == "reject"
        assert result.status == 422


class TestDispatchInterceptPull:
    async def test_no_plugins_proceeds(self) -> None:
        assert (await dispatch_intercept_pull(None, _pull_ctx())).action == "proceed"

    async def test_proceed_falls_through_until_a_respond(self) -> None:
        payload = b"PAR1"

        async def respond(_ctx: PullHookContext) -> InterceptPullResult:
            return InterceptPullResult(
                action="respond", status=200, body=payload, content_type="application/octet-stream"
            )

        plugins = [
            ServerPlugin(name="a", intercept_pull=lambda _ctx: InterceptPullResult(action="proceed")),
            ServerPlugin(name="b", intercept_pull=respond),
        ]
        result = await dispatch_intercept_pull(plugins, _pull_ctx())

        assert result.action == "respond"
        assert result.body == payload
        assert result.content_type == "application/octet-stream"
