import type { AuthProvider, AuthResult, Principal, PrincipalType } from "gapmcp-core";
import { GapError } from "gapmcp-core";
import {
  createLocalJWKSet,
  createRemoteJWKSet,
  jwtVerify,
  type JSONWebKeySet,
  type JWTVerifyGetKey,
  type JWTVerifyOptions,
} from "jose";
import { bearerChallenge } from "./metadata";
import {
  isRecord,
  nonEmptyString,
  readBearerToken,
  uniqueStrings,
} from "./util";

/** Options for {@link jwtAuth}. */
export interface JwtAuthOptions {
  /** Expected `iss` claim. Required when set. */
  issuer?: string;
  /** Expected `aud` claim. Required when set. */
  audience?: string | string[];
  /** HTTPS URL of the authorization server's JWKS document. */
  jwksUri?: string;
  /** Locally supplied JWKS document. Takes precedence over `jwksUri`. */
  jwks?: Record<string, unknown>;
  /** Clock skew tolerance in seconds for `exp` and `nbf`. Defaults to zero. */
  clockToleranceSeconds?: number;
  /**
   * Map verified claims to a principal. Returning `null` rejects the token.
   * When omitted, standard `sub`, `scope`/`scp`, tenant, email, name and type
   * claims are mapped.
   */
  mapClaims?: (claims: Record<string, unknown>) => Principal | null;
}

const MAX_TOKEN_LENGTH = 64 * 1024;
const PRINCIPAL_TYPES = new Set<PrincipalType>([
  "user",
  "service",
  "anonymous",
]);

/**
 * Authenticate `Authorization: Bearer <jwt>` requests with a JWKS.
 *
 * Signatures, issuer, audience and expiry are verified by `jose`, which never
 * accepts `alg: "none"`. A token without `sub` or `exp` is rejected. Successful
 * results expose the raw token, the mapped principal and `expiresAt` in epoch
 * milliseconds.
 */
export function jwtAuth(options: JwtAuthOptions): AuthProvider {
  if (options.jwks === undefined && options.jwksUri === undefined) {
    throw new GapError(
      "jwtAuth requires either jwks or jwksUri.",
      { code: "INVALID_INPUT" },
    );
  }

  const tolerance =
    typeof options.clockToleranceSeconds === "number" &&
    Number.isFinite(options.clockToleranceSeconds) &&
    options.clockToleranceSeconds > 0
      ? options.clockToleranceSeconds
      : 0;

  const verifyOptions: JWTVerifyOptions = {
    requiredClaims: ["exp", "sub"],
    clockTolerance: tolerance,
  };
  if (options.issuer !== undefined) verifyOptions.issuer = options.issuer;
  if (options.audience !== undefined) verifyOptions.audience = options.audience;

  let keyResolver: JWTVerifyGetKey;
  try {
    if (options.jwks !== undefined) {
      if (!isRecord(options.jwks)) {
        throw new TypeError("jwks must be an object.");
      }
      keyResolver = createLocalJWKSet(
        options.jwks as unknown as JSONWebKeySet,
      );
    } else {
      const url = new URL(options.jwksUri as string);
      keyResolver = createRemoteJWKSet(url);
    }
  } catch (cause) {
    throw new GapError("Invalid JWKS configuration.", {
      code: "INVALID_INPUT",
      cause,
    });
  }

  const authenticate = async (request: Request): Promise<AuthResult | null> => {
    const token = readBearerToken(request);
    if (!token || token.length > MAX_TOKEN_LENGTH) return null;
    // Reject obviously malformed tokens before handing them to the verifier.
    if (token.split(".").length !== 3) return null;

    let claims: Record<string, unknown>;
    try {
      const verified = await jwtVerify<Record<string, unknown>>(
        token,
        keyResolver,
        verifyOptions,
      );
      claims = verified.payload;
    } catch {
      return null;
    }

    let principal: Principal | null;
    if (options.mapClaims) {
      try {
        principal = normalizePrincipal(options.mapClaims(claims));
      } catch {
        return null;
      }
    } else {
      principal = principalFromClaims(claims);
    }
    if (!principal) return null;

    const exp = claims.exp;
    if (typeof exp !== "number" || !Number.isFinite(exp)) return null;

    const result: AuthResult = {
      principal,
      token,
      expiresAt: Math.floor(exp * 1000),
    };
    if (principal.scopes && principal.scopes.length > 0) {
      result.scopes = [...principal.scopes];
    }
    const clientId =
      nonEmptyString(claims.client_id) ?? nonEmptyString(claims.azp);
    if (clientId) result.clientId = clientId;
    return result;
  };

  return {
    authenticate,
    challenge: () => bearerChallenge(),
  };
}

function principalFromClaims(
  claims: Record<string, unknown>,
): Principal | null {
  const sub = nonEmptyString(claims.sub);
  if (!sub) return null;

  const principal: Principal = { id: sub };

  const scopes = scopesFromClaims(claims);
  if (scopes.length > 0) principal.scopes = scopes;

  const tenantId =
    nonEmptyString(claims.tenant_id) ?? nonEmptyString(claims.tenantId);
  if (tenantId) principal.tenantId = tenantId;

  const email = nonEmptyString(claims.email);
  if (email) principal.email = email;

  const name = nonEmptyString(claims.name);
  if (name) principal.name = name;

  const type = claims.type;
  if (isPrincipalType(type)) principal.type = type;

  return principal;
}

function scopesFromClaims(claims: Record<string, unknown>): string[] {
  const values: string[] = [];
  collectScopes(claims.scope, values);
  collectScopes(claims.scp, values);
  return uniqueStrings(values);
}

function collectScopes(value: unknown, target: string[]): void {
  if (typeof value === "string") {
    for (const part of value.split(/\s+/)) {
      if (part) target.push(part);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      if (typeof item === "string" && item.length > 0) target.push(item);
    }
  }
}

function normalizePrincipal(value: Principal | null): Principal | null {
  if (!value || typeof value !== "object") return null;
  if (!nonEmptyString(value.id)) return null;

  const principal: Principal = { ...value, id: value.id };
  if (!isPrincipalType(principal.type)) delete principal.type;
  if (!nonEmptyString(principal.tenantId)) delete principal.tenantId;
  if (!nonEmptyString(principal.email)) delete principal.email;
  if (!nonEmptyString(principal.name)) delete principal.name;
  if (principal.scopes !== undefined) {
    if (Array.isArray(principal.scopes)) {
      principal.scopes = uniqueStrings(principal.scopes);
    } else {
      delete principal.scopes;
    }
  }
  if (principal.metadata !== undefined && !isRecord(principal.metadata)) {
    delete principal.metadata;
  }
  return principal;
}

function isPrincipalType(value: unknown): value is PrincipalType {
  return typeof value === "string" && PRINCIPAL_TYPES.has(value as PrincipalType);
}
