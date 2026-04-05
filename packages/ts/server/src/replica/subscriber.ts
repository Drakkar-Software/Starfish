import type { AbstractObjectStore } from "../storage/base.js"

const SUBSCRIPTIONS_KEY = "__sync__/subscriptions.json"

export interface Subscription {
  webhookUrl: string
  collections: string[]
  subscribedAt: number
}

export class SubscriptionStore {
  private readonly store: AbstractObjectStore
  private cache: Subscription[] | null = null

  constructor(store: AbstractObjectStore) {
    this.store = store
  }

  private async load(): Promise<Subscription[]> {
    if (this.cache) return this.cache
    const raw = await this.store.getString(SUBSCRIPTIONS_KEY)
    const subs = raw ? (JSON.parse(raw) as Subscription[]) : []
    this.cache = subs
    return subs
  }

  private async save(subs: Subscription[]): Promise<void> {
    this.cache = subs
    await this.store.put(SUBSCRIPTIONS_KEY, JSON.stringify(subs))
  }

  async add(
    webhookUrl: string,
    collections: string[],
    subscribedAt: number,
  ): Promise<void> {
    const subs = [...(await this.load())]
    const idx = subs.findIndex((s) => s.webhookUrl === webhookUrl)
    const entry: Subscription = { webhookUrl, collections, subscribedAt }
    if (idx >= 0) {
      subs[idx] = entry
    } else {
      subs.push(entry)
    }
    await this.save(subs)
  }

  async remove(webhookUrl: string): Promise<void> {
    const subs = await this.load()
    const filtered = subs.filter((s) => s.webhookUrl !== webhookUrl)
    await this.save(filtered)
  }

  async listForCollection(collectionName: string): Promise<Subscription[]> {
    const subs = await this.load()
    return subs.filter((s) => s.collections.includes(collectionName))
  }

  async listAll(): Promise<Subscription[]> {
    return this.load()
  }
}
