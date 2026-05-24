import type { Queue } from "./base.js"

export class MemoryQueue implements Queue {
  messages: Array<[string, Uint8Array]> = []

  async publish(subject: string, payload: Uint8Array): Promise<void> {
    this.messages.push([subject, payload])
  }
}

type MaybeAsync<T> = T | Promise<T>
type PublishFn = (subject: string, payload: Uint8Array) => MaybeAsync<void>

export class CustomQueue implements Queue {
  private _onPublish?: PublishFn

  constructor(opts: { onPublish?: PublishFn }) {
    this._onPublish = opts.onPublish
  }

  async publish(subject: string, payload: Uint8Array): Promise<void> {
    if (this._onPublish) await this._onPublish(subject, payload)
  }
}
