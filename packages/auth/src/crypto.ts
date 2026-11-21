const textEncoder = new TextEncoder();

/** Encode a string as UTF-8 bytes. */
export function encodeUtf8(value: string): Uint8Array {
  return textEncoder.encode(value);
}

/** Decode UTF-8 bytes, rejecting malformed sequences. */
export function decodeUtf8Strict(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function bytesToBinary(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const chunk = bytes.subarray(offset, offset + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return binary;
}

/** Standard base64 with padding, used for HTTP Basic credentials. */
export function base64Encode(bytes: Uint8Array): string {
  return btoa(bytesToBinary(bytes));
}

/** Unpadded base64url, used in compact approval and handoff tokens. */
export function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;

/** True when a string uses only the base64url alphabet. */
export function isBase64Url(value: string): boolean {
  return BASE64URL_PATTERN.test(value);
}

/** Decode unpadded base64url bytes. Throws on malformed input. */
export function base64UrlDecode(value: string): Uint8Array {
  if (!isBase64Url(value) || value.length % 4 === 1) {
    throw new Error("Invalid base64url encoding.");
  }
  const padding = (4 - (value.length % 4)) % 4;
  const binary = atob(
    value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padding),
  );
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

/** Decode base64url bytes as strict UTF-8 text. Throws on malformed input. */
export function base64UrlDecodeToString(value: string): string {
  return decodeUtf8Strict(base64UrlDecode(value));
}

/** SHA-256 digest as bytes. */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    bytes as BufferSource,
  );
  return new Uint8Array(digest);
}

/**
 * Compare two byte strings without leaking their contents through timing.
 * Length differences are folded into the accumulator instead of returning early.
 */
export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  const length = Math.max(a.length, b.length);
  let difference = a.length ^ b.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (a[index] ?? 0) ^ (b[index] ?? 0);
  }
  return difference === 0;
}

/** Compare two strings without leaking their contents through timing. */
export function timingSafeEqualString(a: string, b: string): boolean {
  return timingSafeEqualBytes(encodeUtf8(a), encodeUtf8(b));
}

/** Cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

/** Import a raw HMAC-SHA256 key. */
export async function importHmacKey(secret: Uint8Array): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    "raw",
    secret as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/** Produce an HMAC-SHA256 signature over raw bytes. */
export async function hmacSha256(
  key: CryptoKey,
  data: Uint8Array,
): Promise<Uint8Array> {
  const signature = await globalThis.crypto.subtle.sign(
    "HMAC",
    key,
    data as BufferSource,
  );
  return new Uint8Array(signature);
}
