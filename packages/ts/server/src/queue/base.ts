export interface Queue {
  connect?(): Promise<void>
  publish(subject: string, payload: Uint8Array): Promise<void>
  close?(): Promise<void>
}
