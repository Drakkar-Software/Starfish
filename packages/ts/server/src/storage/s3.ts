import {
  S3Client,
  GetObjectCommand,
  PutObjectCommand,
  ListObjectsV2Command,
  DeleteObjectCommand,
  DeleteObjectsCommand,
} from "@aws-sdk/client-s3"
import type { ObjectStore, StoreContext } from "./base.js"

export interface S3StorageOptions {
  accessKeyId: string
  secretAccessKey: string
  /** S3-compatible endpoint URL (e.g. "https://s3.amazonaws.com" or a MinIO URL). */
  endpoint: string
  bucket: string
  region?: string
  /**
   * Use path-style addressing (required for most S3-compatible services such as MinIO).
   * Defaults to `true`.
   */
  forcePathStyle?: boolean
}

export class S3ObjectStore implements ObjectStore {
  private _client: S3Client
  private _bucket: string

  constructor(opts: S3StorageOptions) {
    this._bucket = opts.bucket
    this._client = new S3Client({
      endpoint: opts.endpoint,
      region: opts.region ?? "us-east-1",
      credentials: {
        accessKeyId: opts.accessKeyId,
        secretAccessKey: opts.secretAccessKey,
      },
      forcePathStyle: opts.forcePathStyle ?? true,
    })
  }

  async getString(key: string, _context?: StoreContext): Promise<string | null> {
    try {
      const resp = await this._client.send(new GetObjectCommand({ Bucket: this._bucket, Key: key }))
      return await resp.Body!.transformToString("utf-8")
    } catch (e: any) {
      if (e.name === "NoSuchKey") return null
      throw e
    }
  }

  async put(
    key: string,
    body: string,
    opts?: { contentType?: string; cacheControl?: string },
    _context?: StoreContext,
  ): Promise<void> {
    await this._client.send(
      new PutObjectCommand({
        Bucket: this._bucket,
        Key: key,
        Body: body,
        ...(opts?.contentType != null && { ContentType: opts.contentType }),
        ...(opts?.cacheControl != null && { CacheControl: opts.cacheControl }),
      }),
    )
  }

  async getBytes(key: string, _context?: StoreContext): Promise<{ body: Uint8Array; contentType: string } | null> {
    try {
      const resp = await this._client.send(new GetObjectCommand({ Bucket: this._bucket, Key: key }))
      const contentType = resp.ContentType ?? "application/octet-stream"
      const body = await resp.Body!.transformToByteArray()
      return { body, contentType }
    } catch (e: any) {
      if (e.name === "NoSuchKey") return null
      throw e
    }
  }

  async putBytes(
    key: string,
    body: Uint8Array,
    opts: { contentType: string; cacheControl?: string },
    _context?: StoreContext,
  ): Promise<void> {
    await this._client.send(
      new PutObjectCommand({
        Bucket: this._bucket,
        Key: key,
        Body: body,
        ContentType: opts.contentType,
        ...(opts.cacheControl != null && { CacheControl: opts.cacheControl }),
      }),
    )
  }

  async listKeys(
    prefix: string,
    opts?: { startAfter?: string; limit?: number },
    _context?: StoreContext,
  ): Promise<string[]> {
    const resp = await this._client.send(
      new ListObjectsV2Command({
        Bucket: this._bucket,
        Prefix: prefix,
        ...(opts?.startAfter != null && { StartAfter: opts.startAfter }),
        ...(opts?.limit != null && { MaxKeys: opts.limit }),
      }),
    )
    return (resp.Contents ?? []).map((obj) => obj.Key!)
  }

  async delete(key: string, _context?: StoreContext): Promise<void> {
    await this._client.send(new DeleteObjectCommand({ Bucket: this._bucket, Key: key }))
  }

  async deleteMany(keys: string[], _context?: StoreContext): Promise<void> {
    if (keys.length === 0) return
    await this._client.send(
      new DeleteObjectsCommand({
        Bucket: this._bucket,
        Delete: { Objects: keys.map((k) => ({ Key: k })) },
      }),
    )
  }

  /** Destroy the underlying S3 client and release its resources. */
  destroy(): void {
    this._client.destroy()
  }
}
