import { MemoryObjectStore } from "../src/storage/memory.js"

export function createIsolatedStore(): MemoryObjectStore {
  return new MemoryObjectStore({ data: {} })
}
