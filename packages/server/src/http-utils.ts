import type { CorsOptions } from "./types.js";

const DEFAULT_ALLOW_HEADERS = [
  "authorization",
  "content-type",
  "mcp-session-id",
  "mcp-protocol-version",
  "last-event-id",
  "x-api-key",
  "idempotency-key",
  "x-request-id",
];

const DEFAULT_EXPOSE_HEADERS = [
  "mcp-session-id",
  "mcp-protocol-version",
  "www-authenticate",
  "link",
  "x-request-id",
];

const DEFAULT_ALLOW_METHODS = ["GET", "POST", "DELETE", "OPTIONS"];

/** CORS settings after defaults have been applied. */
export type ResolvedCors = false | CorsOptions;

function originAllowed(cors: CorsOptions, origin: string): boolean {
  const policy = cors.origin;
  if (policy === undefined || policy === "*") return true;
  if (typeof policy === "string") return policy === origin;
  if (Array.isArray(policy)) return policy.includes(origin);
  return policy(origin);
}

function reflectedOrigin(cors: CorsOptions, origin: string): string | undefined {
  if (!originAllowed(cors, origin)) return undefined;
  if (cors.credentials) return origin;
  if (cors.origin === undefined || cors.origin === "*") return "*";
  return origin;
}

/**
 * Apply CORS response headers. Returns the allowed origin when one was
 * emitted, which is useful for `Vary` bookkeeping.
 */
export function applyCors(
  headers: Headers,
  request: Request,
  cors: ResolvedCors,
): string | undefined {
  if (cors === false) return undefined;
  const origin = request.headers.get("origin");
  if (!origin) return undefined;

  const allowed = reflectedOrigin(cors, origin);
  if (!allowed) return undefined;

  headers.set("access-control-allow-origin", allowed);
  if (allowed !== "*") headers.append("vary", "Origin");
  headers.set("access-control-allow-methods", (cors.allowMethods ?? DEFAULT_ALLOW_METHODS).join(", "));
  headers.set("access-control-allow-headers", (cors.allowHeaders ?? DEFAULT_ALLOW_HEADERS).join(", "));
  headers.set("access-control-expose-headers", (cors.exposeHeaders ?? DEFAULT_EXPOSE_HEADERS).join(", "));
  headers.set("access-control-max-age", String(cors.maxAge ?? 86_400));
  if (cors.credentials) headers.set("access-control-allow-credentials", "true");
  return allowed;
}

/** True when the request's origin is allowed by the CORS policy. */
export function isOriginAllowed(request: Request, cors: ResolvedCors): boolean {
  if (cors === false) return true;
  const origin = request.headers.get("origin");
  if (!origin) return true;
  return originAllowed(cors, origin);
}

/** Build a JSON response with a no-store cache policy. */
export function jsonResponse(
  status: number,
  body: unknown,
  headers: HeadersInit = {},
): Response {
  const responseHeaders = new Headers(headers);
  if (!responseHeaders.has("content-type")) responseHeaders.set("content-type", "application/json; charset=utf-8");
  responseHeaders.set("cache-control", "no-store");
  return new Response(JSON.stringify(body), { status, headers: responseHeaders });
}

/** Build an MCP-style JSON-RPC error response. */
export function jsonRpcError(status: number, code: number, message: string): Response {
  return jsonResponse(status, { jsonrpc: "2.0", id: null, error: { code, message } });
}

/** Normalise `allowedOrigins`, deriving entries from a configured CORS list. */
export function resolveAllowedOrigins(options: {
  allowedOrigins?: string[];
  cors: ResolvedCors;
}): string[] | undefined {
  const explicit = options.allowedOrigins ? [...options.allowedOrigins] : undefined;
  if (options.cors === false) return explicit;
  const policy = options.cors.origin;
  if (typeof policy === "string" && policy !== "*") {
    return [...new Set([...(explicit ?? []), policy])];
  }
  if (Array.isArray(policy)) {
    return [...new Set([...(explicit ?? []), ...policy])];
  }
  return explicit;
}

function normalizeHost(value: string): string {
  return value.trim().toLowerCase();
}

function stripPort(value: string): string {
  const host = normalizeHost(value);
  if (host.startsWith("[")) {
    const end = host.indexOf("]");
    return end >= 0 ? host.slice(0, end + 1) : host;
  }
  const colon = host.lastIndexOf(":");
  return colon > 0 ? host.slice(0, colon) : host;
}

function hostMatches(host: string, allowed: string): boolean {
  const candidate = normalizeHost(host);
  const entry = normalizeHost(allowed);
  if (entry === "*") return true;
  if (entry === candidate) return true;
  // Entries without an explicit port match any port on that host.
  const entryHasPort = entry.startsWith("[") ? /^\[[^\]]+\]:\d+$/.test(entry) : /:\d+$/.test(entry);
  if (entryHasPort) return false;
  return stripPort(candidate) === entry;
}

/** Options for the DNS-rebinding guard. */
export interface RebindingGuardOptions {
  enabled: boolean;
  allowedHosts?: string[];
  allowedOrigins?: string[];
  baseUrl?: string;
}

const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]", "::1", "0.0.0.0"];

function defaultAllowedHosts(baseUrl: string | undefined): string[] {
  const hosts = [...LOOPBACK_HOSTS];
  if (baseUrl) {
    try {
      hosts.push(new URL(baseUrl).host);
    } catch {
      // An invalid base URL is rejected when the server is constructed.
    }
  }
  return hosts;
}

/**
 * Reject a request whose `Host`/`Origin` headers could indicate DNS
 * rebinding. Returns a 403 response when the request must not be handled.
 */
export function checkRebinding(
  request: Request,
  options: RebindingGuardOptions,
): Response | undefined {
  if (!options.enabled) return undefined;

  const requestUrl = new URL(request.url);
  const host = request.headers.get("host") ?? requestUrl.host;
  const allowedHosts =
    options.allowedHosts && options.allowedHosts.length > 0
      ? options.allowedHosts
      : defaultAllowedHosts(options.baseUrl);

  if (!host || !allowedHosts.some((allowed) => hostMatches(host, allowed))) {
    return jsonResponse(403, {
      error: "forbidden",
      error_description: "The Host header is not allowed by this server.",
    });
  }

  if (options.allowedOrigins && options.allowedOrigins.length > 0) {
    const origin = request.headers.get("origin");
    if (origin) {
      let sameOrigin = false;
      try {
        sameOrigin = origin === requestUrl.origin;
      } catch {
        sameOrigin = false;
      }
      if (!sameOrigin && !options.allowedOrigins.includes(origin)) {
        return jsonResponse(403, {
          error: "forbidden",
          error_description: "The Origin header is not allowed by this server.",
        });
      }
    }
  }

  return undefined;
}

/** True when a parsed JSON-RPC payload contains an `initialize` request. */
export function isInitializePayload(value: unknown): boolean {
  const messages = Array.isArray(value) ? value : [value];
  return messages.some((message) => {
    if (typeof message !== "object" || message === null) return false;
    const record = message as Record<string, unknown>;
    return record.method === "initialize" && record.id !== undefined;
  });
}
