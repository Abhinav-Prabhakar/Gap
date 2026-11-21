import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import type { ServerNotification, ServerRequest } from "@modelcontextprotocol/sdk/types.js";
import type { AuthResult, Principal } from "gapmcp-core";

/** Auth data normalised for one request or transport connection. */
export interface NormalizedAuth {
  principal: Principal;
  scopes: string[];
  token?: string;
  clientId?: string;
  expiresAt?: number;
  extra?: Record<string, unknown>;
}

/** Extra handler data passed to the low-level MCP server. */
export type ToolHandlerExtra = RequestHandlerExtra<ServerRequest, ServerNotification>;

/** The anonymous principal used when no auth provider is configured. */
export const ANONYMOUS_PRINCIPAL: Principal = {
  id: "anonymous",
  type: "anonymous",
  name: "Anonymous",
  scopes: ["*"],
};

/** Build the development-only anonymous auth context. */
export function anonymousAuth(): NormalizedAuth {
  return {
    principal: { ...ANONYMOUS_PRINCIPAL, scopes: ["*"] },
    scopes: ["*"],
  };
}

function dedupeScopes(scopes: readonly string[]): string[] {
  return [...new Set(scopes.filter((scope) => typeof scope === "string" && scope.length > 0))];
}

/**
 * Convert a provider {@link AuthResult} into the server's internal shape.
 * Returns `null` for a result without a usable principal id.
 */
export function normalizeAuthResult(result: AuthResult): NormalizedAuth | null {
  const principal = result.principal;
  if (!principal || typeof principal.id !== "string" || principal.id.trim() === "") return null;
  const scopes = dedupeScopes(result.scopes ?? principal.scopes ?? []);
  return {
    principal: { ...principal, scopes },
    scopes,
    token: result.token,
    clientId: result.clientId,
    expiresAt: result.expiresAt,
    extra: result.extra,
  };
}

/** Build the SDK `AuthInfo` attached to each MCP request. */
export function toAuthInfo(auth: NormalizedAuth): AuthInfo {
  return {
    token: auth.token ?? "",
    clientId: auth.clientId ?? auth.principal.id,
    scopes: [...auth.scopes],
    expiresAt: auth.expiresAt,
    extra: {
      "gap/auth": {
        principal: auth.principal,
        scopes: auth.scopes,
        clientId: auth.clientId,
        expiresAt: auth.expiresAt,
        extra: auth.extra,
      },
    },
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function authFromInfo(info: AuthInfo | undefined): NormalizedAuth | null {
  if (!info) return null;
  const extra = info.extra?.["gap/auth"];
  if (isRecord(extra) && isRecord(extra.principal)) {
    const principal = extra.principal as unknown as Principal;
    if (typeof principal.id !== "string" || principal.id.length === 0) return null;
    const scopes = Array.isArray(extra.scopes)
      ? extra.scopes.filter((scope): scope is string => typeof scope === "string")
      : info.scopes;
    return {
      principal: { ...principal, scopes },
      scopes: [...scopes],
      token: info.token || undefined,
      clientId: info.clientId,
      expiresAt: info.expiresAt,
      extra: isRecord(extra.extra) ? extra.extra : undefined,
    };
  }

  const scopes = Array.isArray(info.scopes) ? [...info.scopes] : [];
  return {
    principal: {
      id: info.clientId || "anonymous",
      type: info.clientId ? "service" : "anonymous",
      scopes,
    },
    scopes,
    token: info.token || undefined,
    clientId: info.clientId,
    expiresAt: info.expiresAt,
  };
}

/**
 * Read the auth context attached to a request by the HTTP layer, falling back
 * to the transport-level principal (used by stdio and custom transports).
 */
export function authFromExtra(extra: ToolHandlerExtra | undefined, fallback: NormalizedAuth): NormalizedAuth {
  return authFromInfo(extra?.authInfo) ?? fallback;
}
