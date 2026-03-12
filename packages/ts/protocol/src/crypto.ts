import { getCrypto } from "./platform.js"

const ALGO = "AES-GCM"
export const IV_BYTES = 12
export const ENCRYPTED_KEY = "_encrypted"

export async function deriveKey(secret: string, salt: string, info: string): Promise<CryptoKey> {
  const enc = new TextEncoder()
  const c = getCrypto()
  const keyMaterial = await c.subtle.importKey(
    "raw",
    enc.encode(secret),
    "HKDF",
    false,
    ["deriveKey"],
  )
  return c.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: enc.encode(salt),
      info: enc.encode(info),
    },
    keyMaterial,
    { name: ALGO, length: 256 },
    false,
    ["encrypt", "decrypt"],
  )
}
