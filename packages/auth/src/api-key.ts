import type { AuthProvider, AuthResult, Principal } from "gapmcp-core";
import { encodeUtf8, sha256, timingSafeEqualBytes } from "./crypto";
import { bearerChallenge } from "./metadata";
import { mergeScopes, readBearerToken } from "./util";

/** A static API key and the principal it authenticates. */
export interface ApiKeyRecord {
  /** The secret key. Empty keys are ignored. */
  key: string;
  /** Identity attached to successful authentication. */
  principal: Principal;
  /** Additional scopes merged with `principal.scopes`. */
  scopes?: string[];
}

/** Resolves an API key record for a request, usually by looking up the key. */
export type ApiKeyResolver = (
  request: Request,
) => ApiKeyRecord | undefined | Promise<ApiKeyRecord | undefined>;

/** Options for {@link apiKeyAuth}. */
export interface ApiKeyAuthOptions {
  /** Static records or a resolver that returns the matching record. */
  keys: ApiKeyRecord[] | ApiKeyResolver;
  /**
   * Restrict key extraction to one header. By default both
   * `Authorization: Bearer <key>` and `X-API-Key: <key>` are accepted.
   */
  header?: "authorization" | "x-api-key";
}

interface PreparedApiKey {
  record: ApiKeyRecord;
  digest: Uint8Array;
}

/**
 * Authenticate requests with API keys.
 *
 * Keys are compared by SHA-256 digest with a constant-time comparison, and the
 * presented key is never logged. Empty keys are rejected. A successful result
 * carries the key's principal, merged scopes, the presented token and the
 * principal id as `clientId`.
 */
export function apiKeyAuth(options: ApiKeyAuthOptions): AuthProvider {
  const source = options.keys;
  const staticKeys =
    typeof source === "function"
      ? undefined
      : source.filter(
          (record) => typeof record.key === "string" && record.key.length > 0,
        );

  let prepared: Promise<PreparedApiKey[]> | undefined;
  const prepare = (): Promise<PreparedApiKey[]> => {
    if (!staticKeys) return Promise.resolve([]);
    prepared ??= Promise.all(
      staticKeys.map(async (record) => ({
        record,
        digest: await sha256(encodeUtf8(record.key)),
      })),
    );
    return prepared;
  };

  const authenticate = async (request: Request): Promise<AuthResult | null> => {
    const candidates = readCandidates(request, options.header);
    if (candidates.length === 0) return null;

    if (typeof source === "function") {
      let record: ApiKeyRecord | undefined;
      try {
        record = await source(request);
      } catch {
        return null;
      }
      if (
        !record ||
        typeof record.key !== "string" ||
        record.key.length === 0
      ) {
        return null;
      }
      const expected = await sha256(encodeUtf8(record.key));
      for (const candidate of candidates) {
        const presented = await sha256(encodeUtf8(candidate));
        if (timingSafeEqualBytes(presented, expected)) {
          return toAuthResult(record, candidate);
        }
      }
      return null;
    }

    const keys = await prepare();
    if (keys.length === 0) return null;

    for (const candidate of candidates) {
      const presented = await sha256(encodeUtf8(candidate));
      let matched: ApiKeyRecord | undefined;
      // Always scan every record so timing does not reveal the matching index.
      for (const entry of keys) {
        if (timingSafeEqualBytes(presented, entry.digest) && !matched) {
          matched = entry.record;
        }
      }
      if (matched) return toAuthResult(matched, candidate);
    }
    return null;
  };

  return {
    authenticate,
    challenge: () => bearerChallenge(),
  };
}

function readCandidates(
  request: Request,
  header: ApiKeyAuthOptions["header"],
): string[] {
  const candidates: string[] = [];
  if (header === undefined || header === "authorization") {
    const bearer = readBearerToken(request);
    if (bearer) candidates.push(bearer);
  }
  if (header === undefined || header === "x-api-key") {
    const value = request.headers.get("x-api-key")?.trim();
    if (value) candidates.push(value);
  }
  return candidates;
}

function toAuthResult(record: ApiKeyRecord, token: string): AuthResult {
  const hasScopes =
    record.principal.scopes !== undefined || record.scopes !== undefined;
  const scopes = mergeScopes(record.principal.scopes, record.scopes);
  const principal: Principal = { ...record.principal };
  if (hasScopes) principal.scopes = scopes;

  const result: AuthResult = {
    principal,
    token,
    clientId: principal.id,
  };
  if (hasScopes) result.scopes = [...scopes];
  return result;
}
