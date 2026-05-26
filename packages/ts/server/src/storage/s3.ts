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
    // S3 returns at most 1000 keys per page. Follow the continuation token so
    // the full key set is returned — the segmented append-only log keys ALL
    // chunks of a single document via `listKeys` (no `limit`), so a truncated
    // first page would silently drop every chunk past the 1000th and the
    // checkpoint bisect would read incomplete data. With a `limit` we stop as
    // soon as it is satisfied. (`StartAfter` is honored only on the first
    // request; the continuation token governs subsequent pages.)
    const keys: string[] = []
    let continuationToken: string | undefined
    do {
      const resp = await this._client.send(
        new ListObjectsV2Command({
          Bucket: this._bucket,
          Prefix: prefix,
          ...(continuationToken == null &&
            opts?.startAfter != null && { StartAfter: opts.startAfter }),
          ...(opts?.limit != null && { MaxKeys: opts.limit }),
          ...(continuationToken != null && { ContinuationToken: continuationToken }),
        }),
      )
      for (const obj of resp.Contents ?? []) keys.push(obj.Key!)
      if (opts?.limit != null && keys.length >= opts.limit) {
        return keys.slice(0, opts.limit)
      }
      continuationToken = resp.IsTruncated ? resp.NextContinuationToken : undefined
    } while (continuationToken != null)
    return keys
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
