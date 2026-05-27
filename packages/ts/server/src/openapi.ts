import type { SyncConfig, CollectionConfig } from "./config/schema.js"
import { ACTION_PULL, ACTION_PUSH, ROLE_PUBLIC } from "./constants.js"

/**
 * Generate an OpenAPI 3.0 specification from a SyncConfig.
 * Produces a spec describing all pull/push endpoints for each collection.
 */
export function generateOpenApiSpec(
  config: SyncConfig,
  options?: {
    title?: string
    version?: string
    serverUrl?: string
  },
): Record<string, unknown> {
  const paths: Record<string, unknown> = {}
  const title = options?.title ?? "Starfish Sync API"
  const version = options?.version ?? "1.0.0"

  // Health endpoint
  paths["/health"] = {
    get: {
      summary: "Health check",
      operationId: "health",
      responses: {
        "200": {
          description: "Server is healthy",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  ok: { type: "boolean" },
                  ts: { type: "number" },
                },
              },
            },
          },
        },
      },
    },
  }

  for (const col of config.collections) {
    if (col.bundle) continue // Bundled collections share paths

    if (!col.pushOnly) {
      paths[`/${ACTION_PULL}/${col.storagePath}`] = {
        get: buildPullOperation(col),
      }
    }

    if (!col.pullOnly) {
      paths[`/${ACTION_PUSH}/${col.storagePath}`] = {
        post: buildPushOperation(col),
      }
    }
  }

  if (config.namespaces) {
    for (const [nsName, nsConfig] of Object.entries(config.namespaces)) {
      // Namespace-scoped batch pull
      paths[`/${nsName}/batch/pull`] = {
        get: {
          summary: `Batch pull (${nsName})`,
          operationId: `batch_pull--${nsName}`,
          parameters: [
            {
              name: "collections",
              in: "query",
              required: true,
              schema: { type: "string" },
              description: `Comma-separated list of collection names in namespace "${nsName}"`,
            },
            {
              name: "params",
              in: "query",
              required: false,
              schema: { type: "string" },
              description:
                'URL-encoded JSON mapping a collection name to an ARRAY of path-param sets (one per document to read), e.g. {"profile":[{"identity":"a"},{"identity":"b"}]}. The {identity} param is auto-filled from the authenticated caller when a set omits it.',
            },
          ],
          responses: {
            "200": {
              description: "Batch pull results",
              content: { "application/json": { schema: { type: "object" } } },
            },
            "400": { description: "Missing collections parameter" },
          },
          security: [{ bearerAuth: [] }],
        },
      }

      for (const col of nsConfig.collections) {
        if (col.bundle) continue

        if (!col.pushOnly) {
          paths[`/${nsName}/${ACTION_PULL}/${col.storagePath}`] = {
            get: buildPullOperation(col, nsName),
          }
        }

        if (!col.pullOnly) {
          paths[`/${nsName}/${ACTION_PUSH}/${col.storagePath}`] = {
            post: buildPushOperation(col, nsName),
          }
        }
      }
    }
  }

  const spec: Record<string, unknown> = {
    openapi: "3.0.3",
    info: { title, version },
    paths,
    components: {
      schemas: {
        PullResponse: {
          type: "object",
          properties: {
            data: { type: "object" },
            hash: { type: "string" },
            timestamp: { type: "number" },
          },
          required: ["data", "hash", "timestamp"],
        },
        PushRequest: {
          type: "object",
          properties: {
            data: { type: "object" },
            baseHash: { type: "string", nullable: true },
            authorSignature: { type: "string" },
          },
          required: ["data", "baseHash"],
        },
        PushResponse: {
          type: "object",
          properties: {
            hash: { type: "string" },
            timestamp: { type: "number" },
          },
          required: ["hash", "timestamp"],
        },
        ErrorResponse: {
          type: "object",
          properties: {
            error: { type: "string" },
          },
          required: ["error"],
        },
      },
    },
  }

  if (options?.serverUrl) {
    spec["servers"] = [{ url: options.serverUrl }]
  }

  return spec
}

function buildPullOperation(col: CollectionConfig, nsName?: string): Record<string, unknown> {
  const isPublic = col.readRoles.includes(ROLE_PUBLIC)
  const params = extractPathParams(col.storagePath)
  const operationId = nsName ? `pull--${nsName}--${col.name}` : `pull_${col.name}`

  const operation: Record<string, unknown> = {
    summary: nsName ? `Pull ${col.name} (${nsName})` : `Pull ${col.name}`,
    operationId,
    parameters: [
      ...params,
      {
        name: "checkpoint",
        in: "query",
        required: false,
        schema: { type: "integer", minimum: 0 },
        description: "Only return data updated after this timestamp",
      },
    ],
    responses: {
      "200": {
        description: "Sync data",
        content: { "application/json": { schema: { $ref: "#/components/schemas/PullResponse" } } },
      },
      "304": { description: "Not Modified (ETag match)" },
      "400": { description: "Invalid request" },
      ...(!isPublic ? { "401": { description: "Unauthorized" }, "403": { description: "Forbidden" } } : {}),
    },
  }

  if (!isPublic) {
    operation["security"] = [{ bearerAuth: [] }]
  }

  return operation
}

function buildPushOperation(col: CollectionConfig, nsName?: string): Record<string, unknown> {
  const params = extractPathParams(col.storagePath)
  const operationId = nsName ? `push--${nsName}--${col.name}` : `push_${col.name}`

  return {
    summary: nsName ? `Push ${col.name} (${nsName})` : `Push ${col.name}`,
    operationId,
    parameters: params,
    requestBody: {
      required: true,
      content: { "application/json": { schema: { $ref: "#/components/schemas/PushRequest" } } },
    },
    responses: {
      "200": {
        description: "Push successful",
        content: { "application/json": { schema: { $ref: "#/components/schemas/PushResponse" } } },
      },
      "400": { description: "Invalid request" },
      "401": { description: "Unauthorized" },
      "403": { description: "Forbidden" },
      "409": { description: "Hash mismatch (conflict)" },
      "413": { description: "Payload too large" },
      "415": { description: "Unsupported content type" },
      "429": { description: "Rate limit exceeded" },
    },
    security: [{ bearerAuth: [] }],
  }
}

function extractPathParams(storagePath: string): Record<string, unknown>[] {
  const matches = storagePath.match(/\{(\w+)\}/g)
  if (!matches) return []
  return matches.map((m) => ({
    name: m.slice(1, -1),
    in: "path",
    required: true,
    schema: { type: "string" },
  }))
}
