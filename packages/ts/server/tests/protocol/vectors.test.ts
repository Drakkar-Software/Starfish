import { describe, it, expect } from "vitest"
import { push } from "../../src/protocol/push.js"
import { pull } from "../../src/protocol/pull.js"
import { computeTimestamps, filterByCheckpoint } from "../../src/protocol/timestamps.js"
import { createIsolatedStore } from "../helpers.js"
import { configurePlatform } from "@drakkarsoftware/starfish-protocol"
import { webcrypto } from "node:crypto"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const pushVectors = JSON.parse(
  readFileSync(resolve(__dirname, "../../../../../tests/test-vectors/protocol-push.json"), "utf-8"),
)
const tsVectors = JSON.parse(
  readFileSync(resolve(__dirname, "../../../../../tests/test-vectors/protocol-timestamps.json"), "utf-8"),
)

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

describe("push vectors - conflict", () => {
  for (const scenario of pushVectors.pushConflict) {
    it(scenario.description, async () => {
      const store = createIsolatedStore()
      let lastHash: string | null = null
      for (const step of scenario.steps) {
        const baseHash =
          step.baseHash === "$previous.hash" ? lastHash : step.baseHash
        const result = await push(
          store,
          scenario.documentKey,
          step.data as Record<string, unknown>,
          baseHash,
        )
        if (step.expect.type === "success") {
          expect("hash" in result).toBe(true)
          lastHash = (result as any).hash
        } else {
          expect("error" in result).toBe(true)
          expect((result as any).error).toBe(step.expect.error)
        }
      }
    })
  }
})

describe("push vectors - success", () => {
  for (const scenario of pushVectors.pushSuccess) {
    it(scenario.description, async () => {
      const store = createIsolatedStore()
      let lastHash: string | null = null
      for (const step of scenario.steps) {
        const baseHash =
          step.baseHash === "$previous.hash" ? lastHash : step.baseHash
        const result = await push(
          store,
          scenario.documentKey,
          step.data as Record<string, unknown>,
          baseHash,
        )
        if (step.expect.type === "success") {
          expect("hash" in result).toBe(true)
          const hash = (result as any).hash as string
          if (step.expect.hashLength) {
            expect(hash).toHaveLength(step.expect.hashLength)
          }
          lastHash = hash
        }
      }
    })
  }
})

describe("push vectors - push then pull", () => {
  for (const scenario of pushVectors.pushThenPull) {
    it(scenario.description, async () => {
      const store = createIsolatedStore()
      let lastHash: string | null = null
      for (const step of scenario.steps) {
        if (step.action === "push") {
          const baseHash =
            step.baseHash === "$previous.hash" ? lastHash : step.baseHash
          const result = await push(
            store,
            scenario.documentKey,
            step.data as Record<string, unknown>,
            baseHash!,
          )
          if (step.expect.type === "success") {
            expect("hash" in result).toBe(true)
            lastHash = (result as any).hash
          }
        } else if (step.action === "pull") {
          const result = await pull(store, scenario.documentKey, step.checkpoint)
          if (step.expect.data) {
            expect(result.data).toEqual(step.expect.data)
          }
          if (step.expect.hashLength) {
            expect(result.hash).toHaveLength(step.expect.hashLength)
          }
        }
      }
    })
  }
})

describe("timestamp vectors - computeTimestamps", () => {
  for (const scenario of tsVectors.computeTimestamps) {
    it(scenario.description, () => {
      const result = computeTimestamps(
        scenario.oldData as any,
        scenario.newData as any,
        scenario.oldTimestamps as any,
        scenario.now,
      )
      expect(result).toEqual(scenario.expected)
    })
  }
})

describe("timestamp vectors - filterByCheckpoint", () => {
  for (const scenario of tsVectors.filterByCheckpoint) {
    it(scenario.description, () => {
      const result = filterByCheckpoint(
        scenario.data as any,
        scenario.timestamps as any,
        scenario.checkpoint,
      )
      expect(result).toEqual(scenario.expected)
    })
  }
})
