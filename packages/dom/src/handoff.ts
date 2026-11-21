import { GapError, invalidInput } from "gapmcp-core";

/** Verified payload carried by a signed human-handoff link. */
export interface HandoffState {
  action: string;
  args: unknown;
  /** Issued-at, milliseconds since the Unix epoch. */
  iat: number;
  /** Expiry, milliseconds since the Unix epoch. */
  exp: number;
  nonce: string;
}

/** Options accepted by {@link createHandoffUrl}. */
export interface CreateHandoffUrlOptions {
  /** App origin, e.g. `https://app.example.com`. */
  baseUrl: string;
  action: string;
  args: unknown;
  secret: string;
  /** Lifetime in milliseconds. Defaults to five minutes. */
  ttlMs?: number;
  /** UI route to link to. Defaults to `/`. Usually `action.ui.route`. */
  path?: string;
}

/** Default lifetime for a human-handoff link. */
export const DEFAULT_HANDOFF_TTL_MS = 5 * 60_000;

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlToBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invalid base64url value.");
  }
  const padded =
    value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

async function sign(payload: string, secret: string): Promise<Uint8Array> {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi?.subtle) {
    throw new GapError("Web Crypto is required to sign handoff state.", {
      code: "UNAVAILABLE",
    });
  }
  const key = await cryptoApi.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await cryptoApi.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload),
  );
  return new Uint8Array(signature);
}

function randomNonce(): string {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi?.getRandomValues) {
    throw new GapError("Secure randomness is required for handoff state.", {
      code: "UNAVAILABLE",
    });
  }
  const bytes = new Uint8Array(16);
  cryptoApi.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

function handoffUrl(baseUrl: string, path: string, token: string): string {
  try {
    const url = new URL(path, baseUrl);
    url.searchParams.set("gap_state", token);
    return url.toString();
  } catch {
    const base = baseUrl.replace(/\/+$/, "");
    const suffix = path.startsWith("/") ? path : `/${path}`;
    const separator = suffix.includes("?") ? "&" : "?";
    return `${base}${suffix}${separator}gap_state=${encodeURIComponent(token)}`;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Create a signed handoff URL. The token is
 * `v1.<base64url(json)>.<base64url(hmac-sha256)>` and the payload contains
 * `{ action, args, iat, exp, nonce }`. Arguments are never added to the URL.
 */
export async function createHandoffUrl(
  options: CreateHandoffUrlOptions,
): Promise<string> {
  if (
    typeof options.action !== "string" ||
    options.action.trim().length === 0
  ) {
    throw invalidInput("A handoff URL needs an action name.");
  }
  if (typeof options.secret !== "string" || options.secret.length === 0) {
    throw invalidInput("A handoff secret is required.");
  }
  const ttlMs = options.ttlMs ?? DEFAULT_HANDOFF_TTL_MS;
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw invalidInput("Handoff ttlMs must be a positive number.");
  }

  const iat = Date.now();
  const payload = {
    action: options.action,
    args: options.args ?? {},
    iat,
    exp: iat + Math.max(1, Math.floor(ttlMs)),
    nonce: randomNonce(),
  };
  const encoded = bytesToBase64Url(
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  const signature = bytesToBase64Url(await sign(encoded, options.secret));
  const token = `v1.${encoded}.${signature}`;
  return handoffUrl(options.baseUrl ?? "", options.path ?? "/", token);
}

/**
 * Verify a handoff token's signature, shape, and expiry. Returns `null` for any
 * malformed, tampered, expired, or wrongly-signed token; never throws.
 */
export async function verifyHandoffState(
  token: string,
  secret: string,
): Promise<HandoffState | null> {
  try {
    if (
      typeof token !== "string" ||
      typeof secret !== "string" ||
      secret.length === 0
    ) {
      return null;
    }
    const parts = token.split(".");
    if (parts.length !== 3 || parts[0] !== "v1") return null;
    const encoded = parts[1];
    const signature = parts[2];
    if (!encoded || !signature) return null;

    const expected = await sign(encoded, secret);
    const provided = base64UrlToBytes(signature);
    if (!constantTimeEqual(expected, provided)) return null;

    const decoded = new TextDecoder().decode(base64UrlToBytes(encoded));
    const payload: unknown = JSON.parse(decoded);
    if (!isRecord(payload)) return null;

    const { action, args, iat, exp, nonce } = payload;
    if (typeof action !== "string" || action.length === 0) return null;
    if (typeof iat !== "number" || !Number.isFinite(iat)) return null;
    if (typeof exp !== "number" || !Number.isFinite(exp) || exp < iat)
      return null;
    if (typeof nonce !== "string" || nonce.length === 0) return null;
    if (Date.now() >= exp) return null;

    return { action, args, iat, exp, nonce };
  } catch {
    return null;
  }
}
