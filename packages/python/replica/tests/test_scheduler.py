"""Tests for ChannelScheduler — the pure scheduling half split out of ReplicaManager.

These drive a fake ReplicaChannel directly (no HTTP, no ObjectStore), which is
the whole point of the split: scheduling is testable without a server.

Note the deliberate behaviour change vs. the pre-split manager, covered by
``test_cooldown_applies_to_a_no_op_sync``: ``_last_sync_at`` is now stamped on
every COMPLETED sync, not only one that actually wrote something. The old
``_do_sync`` stamped it inside the write branch, so a no-op sync (primary hash
unchanged) left the ``on_pull`` cooldown unarmed and every subsequent pull
re-hit the primary. Mirrors TS ``scheduler.ts``.
"""

from __future__ import annotations

import asyncio

import pytest

from starfish_replica.channel import ChannelSchedule, ReplicaCallContext, ScheduledChannel, SyncTrigger
from starfish_replica.scheduler import ChannelScheduler, default_scheduler_on_error


class FakeChannel:
    """Counts syncs; optionally raises, or blocks until released."""

    def __init__(self, name: str = "fake", *, raises: Exception | None = None) -> None:
        self.name = name
        self.raises = raises
        self.sync_calls = 0
        self.seen_contexts: list[ReplicaCallContext] = []
        self.gate: asyncio.Event | None = None

    async def sync(self, ctx: ReplicaCallContext) -> None:
        self.sync_calls += 1
        self.seen_contexts.append(ctx)
        if self.gate is not None:
            await self.gate.wait()
        if self.raises is not None:
            raise self.raises


def _entry(channel: FakeChannel, **schedule_kwargs) -> ScheduledChannel:
    schedule_kwargs.setdefault("triggers", [SyncTrigger.SCHEDULED])
    return ScheduledChannel(channel=channel, schedule=ChannelSchedule(**schedule_kwargs))


# ── sync_now / sync_all ───────────────────────────────────────────────────────


async def test_sync_now_drives_the_channel():
    ch = FakeChannel()
    scheduler = ChannelScheduler([_entry(ch)])

    await scheduler.sync_now("fake")

    assert ch.sync_calls == 1


async def test_sync_now_unknown_channel_raises_with_the_legacy_message():
    # Message pinned byte-for-byte: tests/test_manager.py matches on
    # "Unknown remote collection" via pytest.raises(match=...).
    scheduler = ChannelScheduler([])
    with pytest.raises(ValueError, match="Unknown remote collection"):
        await scheduler.sync_now("nope")


async def test_sync_now_propagates_channel_errors():
    ch = FakeChannel(raises=RuntimeError("boom"))
    scheduler = ChannelScheduler([_entry(ch)])

    with pytest.raises(RuntimeError, match="boom"):
        await scheduler.sync_now("fake")


async def test_sync_all_fans_out_to_every_channel():
    a, b, c = FakeChannel("a"), FakeChannel("b"), FakeChannel("c")
    scheduler = ChannelScheduler([_entry(a), _entry(b), _entry(c)])

    await scheduler.sync_all()

    assert (a.sync_calls, b.sync_calls, c.sync_calls) == (1, 1, 1)


async def test_sync_all_runs_channels_concurrently_not_serially():
    a, b = FakeChannel("a"), FakeChannel("b")
    a.gate = asyncio.Event()
    b.gate = asyncio.Event()
    scheduler = ChannelScheduler([_entry(a), _entry(b)])

    task = asyncio.create_task(scheduler.sync_all())
    await asyncio.sleep(0)  # let both start
    await asyncio.sleep(0)
    # Both entered sync before either was released — proves they overlap.
    assert (a.sync_calls, b.sync_calls) == (1, 1)
    a.gate.set()
    b.gate.set()
    await task


async def test_sync_all_isolates_a_failing_channel_from_the_others():
    bad = FakeChannel("bad", raises=RuntimeError("boom"))
    good = FakeChannel("good")
    errors: list[tuple[str, Exception]] = []
    scheduler = ChannelScheduler(
        [_entry(bad), _entry(good)], on_error=lambda n, e: errors.append((n, e))
    )

    await scheduler.sync_all()  # must not raise

    assert good.sync_calls == 1
    assert [n for n, _ in errors] == ["bad"]


# ── error funnel ──────────────────────────────────────────────────────────────


async def test_sync_safe_funnels_exceptions_into_on_error():
    ch = FakeChannel(raises=ValueError("nope"))
    errors: list[tuple[str, Exception]] = []
    scheduler = ChannelScheduler([_entry(ch)], on_error=lambda n, e: errors.append((n, e)))

    await scheduler.on_pull("fake")  # on_pull goes through _sync_safe

    assert len(errors) == 1
    assert errors[0][0] == "fake"
    assert isinstance(errors[0][1], ValueError)


async def test_default_on_error_logs_and_does_not_raise(caplog):
    # The default handler must never itself throw — it is the last line of
    # defence inside a background task.
    default_scheduler_on_error("some-channel", RuntimeError("kaboom"))


async def test_a_failing_channel_does_not_stamp_the_cooldown():
    # A sync that raised did not successfully contact the primary, so it must
    # not arm the on_pull cooldown — otherwise one failure would suppress
    # retries for the whole cooldown window.
    ch = FakeChannel(raises=RuntimeError("boom"))
    scheduler = ChannelScheduler(
        [_entry(ch, triggers=[SyncTrigger.ON_PULL], on_pull_min_interval_ms=60_000)],
        on_error=lambda n, e: None,
    )

    await scheduler.on_pull("fake")
    await scheduler.on_pull("fake")

    assert ch.sync_calls == 2  # not suppressed by a cooldown from the failed attempt


# ── on_pull + cooldown ────────────────────────────────────────────────────────


async def test_on_pull_syncs_when_no_cooldown_configured():
    ch = FakeChannel()
    scheduler = ChannelScheduler([_entry(ch, triggers=[SyncTrigger.ON_PULL])])

    await scheduler.on_pull("fake")
    await scheduler.on_pull("fake")

    assert ch.sync_calls == 2


async def test_on_pull_respects_the_cooldown_window():
    ch = FakeChannel()
    scheduler = ChannelScheduler(
        [_entry(ch, triggers=[SyncTrigger.ON_PULL], on_pull_min_interval_ms=60_000)]
    )

    await scheduler.on_pull("fake")
    await scheduler.on_pull("fake")

    assert ch.sync_calls == 1


async def test_on_pull_syncs_again_once_the_cooldown_expires():
    import time

    ch = FakeChannel()
    scheduler = ChannelScheduler(
        [_entry(ch, triggers=[SyncTrigger.ON_PULL], on_pull_min_interval_ms=1)]
    )

    await scheduler.on_pull("fake")
    scheduler._last_sync_at["fake"] = time.monotonic() - 1.0  # force expiry
    await scheduler.on_pull("fake")

    assert ch.sync_calls == 2


async def test_cooldown_applies_to_a_no_op_sync():
    """The deliberate behaviour change vs. the pre-split manager.

    FakeChannel.sync() writes nothing at all — it is a pure no-op. The old
    manager only stamped _last_sync_at inside the successful-write branch, so
    this case left the cooldown unarmed forever. The scheduler now stamps on
    every completed sync, so a no-op still arms it.
    """
    ch = FakeChannel()
    scheduler = ChannelScheduler(
        [_entry(ch, triggers=[SyncTrigger.ON_PULL], on_pull_min_interval_ms=60_000)]
    )

    await scheduler.on_pull("fake")
    await scheduler.on_pull("fake")
    await scheduler.on_pull("fake")

    assert ch.sync_calls == 1


async def test_on_pull_for_an_unknown_channel_is_a_silent_noop():
    # Unlike sync_now, on_pull must not raise — it runs on the request path for
    # every collection, most of which are not replicated at all.
    scheduler = ChannelScheduler([])
    await scheduler.on_pull("not-registered")  # must not raise


async def test_cooldown_is_tracked_per_channel_not_globally():
    a, b = FakeChannel("a"), FakeChannel("b")
    scheduler = ChannelScheduler([
        _entry(a, triggers=[SyncTrigger.ON_PULL], on_pull_min_interval_ms=60_000),
        _entry(b, triggers=[SyncTrigger.ON_PULL], on_pull_min_interval_ms=60_000),
    ])

    await scheduler.on_pull("a")
    await scheduler.on_pull("b")  # b has its own window; a's must not suppress it

    assert (a.sync_calls, b.sync_calls) == (1, 1)


# ── call context ──────────────────────────────────────────────────────────────


async def test_channel_receives_the_replicator_context():
    ch = FakeChannel()
    scheduler = ChannelScheduler([_entry(ch)])

    await scheduler.sync_now("fake")

    assert ch.seen_contexts[0].call_kind == "replicator"


# ── start / stop ──────────────────────────────────────────────────────────────


async def test_start_runs_an_interval_loop_for_scheduled_channels():
    ch = FakeChannel()
    scheduler = ChannelScheduler([_entry(ch, interval_ms=10)])

    await scheduler.start()
    await asyncio.sleep(0.05)
    await scheduler.stop()

    assert ch.sync_calls >= 2  # looped, not a single fire


async def test_start_fires_once_for_a_non_scheduled_channel():
    ch = FakeChannel()
    scheduler = ChannelScheduler([_entry(ch, triggers=[SyncTrigger.ON_PULL])])

    await scheduler.start()
    await asyncio.sleep(0.03)
    await scheduler.stop()

    assert ch.sync_calls == 1  # initial sync only — no loop task


async def test_stop_cancels_the_loop():
    ch = FakeChannel()
    scheduler = ChannelScheduler([_entry(ch, interval_ms=10)])

    await scheduler.start()
    await asyncio.sleep(0.03)
    await scheduler.stop()
    calls_at_stop = ch.sync_calls
    await asyncio.sleep(0.05)

    assert ch.sync_calls == calls_at_stop  # no further syncs after stop


async def test_stop_is_idempotent():
    scheduler = ChannelScheduler([_entry(FakeChannel(), interval_ms=10)])
    await scheduler.start()
    await scheduler.stop()
    await scheduler.stop()  # must not raise


async def test_stop_without_start_is_safe():
    scheduler = ChannelScheduler([_entry(FakeChannel())])
    await scheduler.stop()  # must not raise


async def test_loop_survives_a_failing_sync_and_keeps_going():
    ch = FakeChannel(raises=RuntimeError("boom"))
    errors: list[str] = []
    scheduler = ChannelScheduler(
        [_entry(ch, interval_ms=10)], on_error=lambda n, e: errors.append(n)
    )

    await scheduler.start()
    await asyncio.sleep(0.05)
    await scheduler.stop()

    assert ch.sync_calls >= 2  # kept looping despite raising every time
    assert len(errors) >= 2


async def test_start_with_no_entries_is_safe():
    scheduler = ChannelScheduler([])
    await scheduler.start()
    await scheduler.stop()


async def test_interval_defaults_when_schedule_omits_it():
    # ChannelSchedule.interval_ms is Optional; the loop must fall back rather
    # than divide by None.
    ch = FakeChannel()
    scheduler = ChannelScheduler([_entry(ch)])  # interval_ms=None

    await scheduler.start()
    await asyncio.sleep(0.02)
    await scheduler.stop()

    assert ch.sync_calls == 1  # fired once immediately, then waits the 60s default
