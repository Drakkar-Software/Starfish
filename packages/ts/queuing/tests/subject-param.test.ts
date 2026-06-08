/**
 * `QueueConfig.subjectParam` — per-resource subject derivation (TS parity with the
 * Python `tests/test_subject_param.py`).
 *
 * These drive the plugin's `afterWrite` hook **directly** (the same hook the sync
 * router invokes after a push), handing it a `WriteEvent`. That exercises the whole
 * config → subject path without the server/crypto stack, and is the ONLY way to
 * cover the charset re-validation: an HTTP push can never deliver a
 * metacharacter-bearing id — the upstream route/role gate rejects `foo.bar` before
 * the plugin runs — so the queuing layer's defensive `RegExp.test` (which guards
 * against future gate drift) must be probed by feeding the plugin a bad id directly.
 * A rejected id falls back to the base subject; the broker never sees a `.`/`*`/`>`
 * token. (The HTTP-router integration path is covered by the Python suite; the
 * wiring is identical across languages.)
 *
 * Imports stay within `starfish-queuing` (its protocol import is type-only, erased
 * at runtime) so the suite runs independently of the workspace's protocol build.
 */

import { describe, it, expect } from "vitest"
import type { WriteEvent } from "@drakkar.software/starfish-protocol"
import {
  DEFAULT_SAFE_ID,
  MemoryQueue,
  createQueuingServerPlugin,
  type QueueConfig,
} from "../src/index.js"

/** Drive the plugin's publish path directly and return the resulting subject. */
async function publishSubject(cfg: QueueConfig, params: Record<string, string>): Promise<string> {
  const queue = new MemoryQueue()
  const plugin = createQueuingServerPlugin({ queue, collections: { posts: cfg } })
  const event: WriteEvent = { collection: "posts", hash: "h", timestamp: 1, params }
  await plugin.afterWrite!(event)
  expect(queue.messages).toHaveLength(1)
  return queue.messages[0]![0]
}

describe("QueueConfig.subjectParam — subject derivation", () => {
  it("appends the route param value to the subject", async () => {
    expect(
      await publishSubject({ topic: "posts.changed", subjectParam: "postId", includeParams: false }, { postId: "my-post-id" }),
    ).toBe("posts.changed.my-post-id")
  })

  it("derives the suffix independently of includeParams", async () => {
    // includeParams is false here, yet the suffix is still derived — it is read
    // from WriteEvent.params, not from the serialized message body. (The body
    // contents are covered by plugin.test.ts; here we only assert the subject.)
    expect(
      await publishSubject({ topic: "posts.changed", subjectParam: "postId", includeParams: false }, { postId: "abc" }),
    ).toBe("posts.changed.abc")
  })

  it("falls back to the collection-name base when topic is unset", async () => {
    expect(await publishSubject({ subjectParam: "postId", includeParams: false }, { postId: "abc" })).toBe("posts.abc")
  })

  it("appends a valid id with the safe charset", async () => {
    expect(
      await publishSubject({ topic: "posts.changed", subjectParam: "postId", includeParams: false }, { postId: "p_1-A" }),
    ).toBe("posts.changed.p_1-A")
  })
})

describe("QueueConfig.subjectParam — charset re-validation (defense-in-depth)", () => {
  it("DEFAULT_SAFE_ID is the safe-id charset, no g flag", () => {
    expect(DEFAULT_SAFE_ID.source).toBe("^[a-zA-Z0-9_-]+$")
    expect(DEFAULT_SAFE_ID.global).toBe(false)
  })

  it.each(["foo.bar", "foo*bar", "foo>bar", "foo bar", "foo\n", "\nfoo", "foo/bar", ""])(
    "metachar id %j falls back to the base subject",
    async (badId) => {
      expect(
        await publishSubject({ topic: "posts.changed", subjectParam: "postId", includeParams: false }, { postId: badId }),
      ).toBe("posts.changed")
    },
  )

  it("missing param falls back to the base subject", async () => {
    expect(await publishSubject({ topic: "posts.changed", subjectParam: "postId", includeParams: false }, {})).toBe("posts.changed")
  })

  it("honors a custom subjectIdPattern", async () => {
    const cfg: QueueConfig = { topic: "posts.changed", subjectParam: "postId", subjectIdPattern: /^[0-9]+$/, includeParams: false }
    expect(await publishSubject(cfg, { postId: "abc" })).toBe("posts.changed")
    expect(await publishSubject(cfg, { postId: "123" })).toBe("posts.changed.123")
  })

  it("leaves the subject unchanged when subjectParam is unset", async () => {
    expect(await publishSubject({ topic: "posts.changed", includeParams: false }, { postId: "abc" })).toBe("posts.changed")
  })
})
