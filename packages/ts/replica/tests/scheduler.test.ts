/**
 * `ChannelScheduler` — the pure scheduling half extracted from `ReplicaManager`.
 *
 * `manager.test.ts` exercises this class transitively through the back-compat
 * HTTP constructor, but only ever with a `RemoteCollection`-derived schedule,
 * where `intervalMs` is REQUIRED (`config.ts`). The direct-construction path
 * `./space` documents (`new ReplicaManager([{ channel, schedule }])`) takes a
 * `ChannelSchedule`, where `intervalMs` is OPTIONAL — a shape nothing covered
 * until now. Ported from Python's `test_scheduler.py`, which had this from the
 * start.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { ChannelScheduler } from "../src/scheduler.js"
import type { ReplicaCallContext, ReplicaChannel } from "../src/channel.js"

/** Records every `sync()` and the context it was handed. */
function fakeChannel(name: string, opts?: { fail?: boolean }) {
  const calls: ReplicaCallContext[] = []
  const channel: ReplicaChannel = {
    name,
    async sync(ctx) {
      calls.push(ctx)
      if (opts?.fail) throw new Error(`${name} boom`)
    },
  }
  return { channel, calls }
}

describe("ChannelScheduler — interval loop", () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it("regression: a scheduled entry that omits intervalMs does NOT spin a 0ms loop", async () => {
    // The bug: `setInterval(fn, intervalMs ?? 0)` fires as fast as the event
    // loop allows, hammering the network instead of doing nothing visible.
    // Python's scheduler.py has always defaulted to 60s (`interval_ms or 60_000`).
    const { channel, calls } = fakeChannel("c1")
    const sched = new ChannelScheduler([{ channel, schedule: { triggers: ["scheduled"] } }])

    sched.start()
    expect(calls).toHaveLength(1) // the initial sync

    // A 0ms interval would have fired ~59 more times by here.
    await vi.advanceTimersByTimeAsync(59_000)
    expect(calls).toHaveLength(1)

    await vi.advanceTimersByTimeAsync(1_500)
    expect(calls).toHaveLength(2)

    sched.stop()
  })

  it("honours an explicit intervalMs", async () => {
    const { channel, calls } = fakeChannel("c1")
    const sched = new ChannelScheduler([
      { channel, schedule: { triggers: ["scheduled"], intervalMs: 1_000 } },
    ])

    sched.start()
    await vi.advanceTimersByTimeAsync(3_000)
    expect(calls).toHaveLength(4) // initial + 3

    sched.stop()
  })

  it("stop() cancels the loop", async () => {
    const { channel, calls } = fakeChannel("c1")
    const sched = new ChannelScheduler([
      { channel, schedule: { triggers: ["scheduled"], intervalMs: 1_000 } },
    ])

    sched.start()
    await vi.advanceTimersByTimeAsync(2_000)
    const seen = calls.length
    sched.stop()
    await vi.advanceTimersByTimeAsync(10_000)

    expect(calls).toHaveLength(seen)
  })

  it("a non-scheduled entry syncs once at start and never loops", async () => {
    const { channel, calls } = fakeChannel("c1")
    const sched = new ChannelScheduler([{ channel, schedule: { triggers: ["on_pull"] } }])

    sched.start()
    await vi.advanceTimersByTimeAsync(120_000)
    expect(calls).toHaveLength(1)

    sched.stop()
  })

  it("keeps looping after a failing sync", async () => {
    const { channel } = fakeChannel("c1", { fail: true })
    const onError = vi.fn()
    const sched = new ChannelScheduler(
      [{ channel, schedule: { triggers: ["scheduled"], intervalMs: 1_000 } }],
      { onError },
    )

    sched.start()
    await vi.advanceTimersByTimeAsync(3_000)
    expect(onError.mock.calls.length).toBeGreaterThanOrEqual(3)
    expect(onError.mock.calls[0]![0]).toBe("c1")

    sched.stop()
  })
})

describe("ChannelScheduler — on_pull cooldown", () => {
  it("syncs on every on_pull when no cooldown is configured", async () => {
    const { channel, calls } = fakeChannel("c1")
    const sched = new ChannelScheduler([{ channel, schedule: { triggers: ["on_pull"] } }])

    await sched.onPull("c1")
    await sched.onPull("c1")
    expect(calls).toHaveLength(2)
  })

  it("suppresses a second on_pull inside the cooldown window", async () => {
    const { channel, calls } = fakeChannel("c1")
    const sched = new ChannelScheduler([
      { channel, schedule: { triggers: ["on_pull"], onPullMinIntervalMs: 60_000 } },
    ])

    await sched.onPull("c1")
    await sched.onPull("c1")
    expect(calls).toHaveLength(1)
  })

  it("a failing sync does not stamp the cooldown", async () => {
    // Otherwise one transient failure locks out retries for the whole window.
    const { channel } = fakeChannel("c1", { fail: true })
    const onError = vi.fn()
    const sched = new ChannelScheduler(
      [{ channel, schedule: { triggers: ["on_pull"], onPullMinIntervalMs: 60_000 } }],
      { onError },
    )

    await sched.onPull("c1")
    await sched.onPull("c1")
    expect(onError).toHaveBeenCalledTimes(2)
  })

  it("on_pull for an unknown channel is a silent no-op", async () => {
    const sched = new ChannelScheduler([])
    await expect(sched.onPull("nope")).resolves.toBeUndefined()
  })

  it("tracks the cooldown per channel, not globally", async () => {
    const a = fakeChannel("a")
    const b = fakeChannel("b")
    const sched = new ChannelScheduler([
      { channel: a.channel, schedule: { triggers: ["on_pull"], onPullMinIntervalMs: 60_000 } },
      { channel: b.channel, schedule: { triggers: ["on_pull"], onPullMinIntervalMs: 60_000 } },
    ])

    await sched.onPull("a")
    await sched.onPull("b")
    expect(a.calls).toHaveLength(1)
    expect(b.calls).toHaveLength(1)
  })
})

describe("ChannelScheduler — syncNow / syncAll", () => {
  it("syncNow drives exactly the named channel", async () => {
    const a = fakeChannel("a")
    const b = fakeChannel("b")
    const sched = new ChannelScheduler([
      { channel: a.channel, schedule: { triggers: [] } },
      { channel: b.channel, schedule: { triggers: [] } },
    ])

    await sched.syncNow("a")
    expect(a.calls).toHaveLength(1)
    expect(b.calls).toHaveLength(0)
  })

  it("syncNow throws for an unknown channel, with the legacy message", async () => {
    const sched = new ChannelScheduler([])
    await expect(sched.syncNow("nope")).rejects.toThrow(
      '[ReplicaManager] Unknown remote collection: "nope"',
    )
  })

  it("syncNow propagates the channel's error (unlike the scheduled path)", async () => {
    const { channel } = fakeChannel("c1", { fail: true })
    const sched = new ChannelScheduler([{ channel, schedule: { triggers: [] } }])
    await expect(sched.syncNow("c1")).rejects.toThrow("c1 boom")
  })

  it("syncAll fans out to every channel and isolates a failure", async () => {
    const good = fakeChannel("good")
    const bad = fakeChannel("bad", { fail: true })
    const onError = vi.fn()
    const sched = new ChannelScheduler(
      [
        { channel: good.channel, schedule: { triggers: [] } },
        { channel: bad.channel, schedule: { triggers: [] } },
      ],
      { onError },
    )

    await expect(sched.syncAll()).resolves.toBeUndefined()
    expect(good.calls).toHaveLength(1)
    expect(onError).toHaveBeenCalledWith("bad", expect.any(Error))
  })

  it("passes the replicator context to the channel", async () => {
    const { channel, calls } = fakeChannel("c1")
    const sched = new ChannelScheduler([{ channel, schedule: { triggers: [] } }])

    await sched.syncNow("c1")
    expect(calls[0]).toEqual({ callKind: "replicator" })
  })
})
