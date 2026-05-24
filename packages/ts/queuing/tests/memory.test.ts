import { describe, it, expect } from "vitest"
import { MemoryQueue, CustomQueue } from "../src/memory.js"

describe("MemoryQueue", () => {
  it("records published messages", async () => {
    const queue = new MemoryQueue()
    const payload = new TextEncoder().encode('{"test":true}')
    await queue.publish("topic-1", payload)
    expect(queue.messages).toHaveLength(1)
    expect(queue.messages[0]![0]).toBe("topic-1")
    expect(new TextDecoder().decode(queue.messages[0]![1])).toBe('{"test":true}')
  })
})

describe("CustomQueue", () => {
  it("delegates to callback", async () => {
    const calls: Array<[string, Uint8Array]> = []
    const queue = new CustomQueue({
      onPublish: (subject, payload) => {
        calls.push([subject, payload])
      },
    })
    const payload = new TextEncoder().encode("data")
    await queue.publish("sub", payload)
    expect(calls).toHaveLength(1)
    expect(calls[0]![0]).toBe("sub")
  })

  it("no-op when no callback", async () => {
    const queue = new CustomQueue({})
    await queue.publish("sub", new TextEncoder().encode("data"))
  })
})
