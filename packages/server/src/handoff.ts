import { canonicalJson, createId, hashValue } from "gapmcp-core";

/**
 * Decoded handoff state carried in a `gap_state` query parameter.
 * The token format matches `gapmcp-dom`: `v1.<base64url json>.<hmac>`.
 */
export interface SignedHandoffState {
  v: 1;
  action: string;
  args: unknown;
  argsHash: string;
  principalId: string;
  tenantId?: string;
  iat: number;
  exp: number;
  nonce: string;
}

/** Options for {@link createSignedHandoffLink}. */
export interface CreateSignedHandoffLinkOptions {
  secret: string;
  action: string;
  args?: unknown;
  principalId: string;
  tenantId?: string;
  /** Absolute application base URL, e.g. `https://app.example.com`. */
  baseUrl?: string;
  /** Route to open. Defaults to `/`. */
  route?: string;
  /** Token lifetime. Defaults to ten minutes. */
  ttlMs?: number;
  /** Clock injection for tests. */
  now?: () => number;
}

/** A generated handoff URL plus the token it carries. */
export interface SignedHandoffLink {
  url: string;
  token: string;
  expiresAt: number;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const DEFAULT_TTL_MS = 10 * 60_000;

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes;
  } catch {
    return null;
  }
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
    "verify",
  ]);
}

function appendState(route: string, token: string): string {
  const hashIndex = route.indexOf("#");
  const beforeHash = hashIndex >= 0 ? route.slice(0, hashIndex) : route;
  const hash = hashIndex >= 0 ? route.slice(hashIndex) : "";
  const separator = beforeHash.includes("?") ? "&" : "?";
  return `${beforeHash}${separator}gap_state=${encodeURIComponent(token)}${hash}`;
}

function resolveUrl(baseUrl: string | undefined, route: string): string {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(route)) return route;
  if (!baseUrl) return route.startsWith("/") ? route : `/${route}`;
  const base = baseUrl.replace(/\/+$/g, "");
  return `${base}${route.startsWith("/") ? "" : "/"}${route}`;
}

/**
 * Create a signed deep link that hands an action invocation to a browser UI.
 * The signature covers `v1.<payload>`, so neither the target action nor its
 * arguments can be changed without invalidating the token.
 */
export async function createSignedHandoffLink(
  options: CreateSignedHandoffLinkOptions,
): Promise<SignedHandoffLink> {
  if (!options.secret) throw new Error("A handoff secret is required.");
  if (!options.action) throw new Error("A handoff action is required.");
  if (!options.principalId) throw new Error("A handoff principal is required.");

  const now = options.now ?? Date.now;
  const issuedAt = now();
  const ttlMs = options.ttlMs && options.ttlMs > 0 ? options.ttlMs : DEFAULT_TTL_MS;
  const args = options.args ?? {};
  const state: SignedHandoffState = {
    v: 1,
    action: options.action,
    args,
    argsHash: await hashValue(args),
    principalId: options.principalId,
    ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
    iat: issuedAt,
    exp: issuedAt + ttlMs,
    nonce: createId("hs"),
  };

  const payload = toBase64Url(encoder.encode(canonicalJson(state)));
  const signingInput = `v1.${payload}`;
  const signature = await crypto.subtle.sign("HMAC", await hmacKey(options.secret), encoder.encode(signingInput));
  const token = `${signingInput}.${toBase64Url(new Uint8Array(signature))}`;
  const url = appendState(resolveUrl(options.baseUrl, options.route ?? "/"), token);
  return { url, token, expiresAt: state.exp };
}

/** Options for {@link verifySignedHandoffLink}. */
export interface VerifySignedHandoffLinkOptions {
  /** Also require the token to name this action. */
  action?: string;
  /** Also require the token's arguments to hash to the same value. */
  args?: unknown;
  now?: () => number;
}

/**
 * Verify a handoff token. Returns `null` for malformed, tampered, expired or
 * mismatched tokens; never throws on attacker-controlled input.
 */
export async function verifySignedHandoffLink(
  token: string,
  secret: string,
  options: VerifySignedHandoffLinkOptions = {},
): Promise<SignedHandoffState | null> {
  if (!token || !secret) return null;
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return null;
  const payload = parts[1];
  const signature = parts[2];
  if (!payload || !signature) return null;

  const signatureBytes = fromBase64Url(signature);
  if (!signatureBytes) return null;
  let valid = false;
  try {
    valid = await crypto.subtle.verify(
      "HMAC",
      await hmacKey(secret),
      new Uint8Array(signatureBytes),
      new Uint8Array(encoder.encode(`v1.${payload}`)),
    );
  } catch {
    return null;
  }
  if (!valid) return null;

  const payloadBytes = fromBase64Url(payload);
  if (!payloadBytes) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoder.decode(payloadBytes));
  } catch {
    return null;
  }
  if (!isSignedHandoffState(parsed)) return null;

  const now = options.now ?? Date.now;
  if (parsed.exp <= now()) return null;
  if (options.action !== undefined && parsed.action !== options.action) return null;
  if (options.args !== undefined && parsed.argsHash !== (await hashValue(options.args))) return null;
  return parsed;
}

function isSignedHandoffState(value: unknown): value is SignedHandoffState {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    record.v === 1 &&
    typeof record.action === "string" &&
    typeof record.argsHash === "string" &&
    typeof record.principalId === "string" &&
    typeof record.iat === "number" &&
    typeof record.exp === "number" &&
    typeof record.nonce === "string"
  );
}
