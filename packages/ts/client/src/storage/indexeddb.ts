/**
 * IndexedDB-based storage adapter for Zustand persistence.
 * Implements the same interface as Zustand's StateStorage (getItem/setItem/removeItem).
 * Supports larger data than localStorage (typically 50MB+).
 */

export interface IndexedDBStorageOptions {
  /** Database name. Default: "starfish" */
  dbName?: string
  /** Object store name. Default: "state" */
  storeName?: string
}

export interface AsyncStateStorage {
  getItem: (name: string) => Promise<string | null>
  setItem: (name: string, value: string) => Promise<void>
  removeItem: (name: string) => Promise<void>
}

function openDB(dbName: string, storeName: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(dbName, 1)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(storeName)) {
        db.createObjectStore(storeName)
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

function idbRequest<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

export function createIndexedDBStorage(
  opts?: IndexedDBStorageOptions,
): AsyncStateStorage {
  const dbName = opts?.dbName ?? "starfish"
  const storeName = opts?.storeName ?? "state"
  let dbPromise: Promise<IDBDatabase> | null = null

  function getDB(): Promise<IDBDatabase> {
    if (!dbPromise) {
      dbPromise = openDB(dbName, storeName).catch((err) => {
        dbPromise = null // Reset so next call retries
        throw err
      })
    }
    return dbPromise
  }

  return {
    async getItem(name: string): Promise<string | null> {
      const db = await getDB()
      const tx = db.transaction(storeName, "readonly")
      const store = tx.objectStore(storeName)
      const result = await idbRequest(store.get(name))
      return result ?? null
    },

    async setItem(name: string, value: string): Promise<void> {
      const db = await getDB()
      const tx = db.transaction(storeName, "readwrite")
      const store = tx.objectStore(storeName)
      await idbRequest(store.put(value, name))
    },

    async removeItem(name: string): Promise<void> {
      const db = await getDB()
      const tx = db.transaction(storeName, "readwrite")
      const store = tx.objectStore(storeName)
      await idbRequest(store.delete(name))
    },
  }
}
