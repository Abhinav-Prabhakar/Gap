import { GapError, type GapErrorCode, type RiskLevel } from "gapmcp-core";

/** The subset of HTTP methods understood by both importers. */
export type ImportedHttpMethod =
  | "get"
  | "post"
  | "put"
  | "patch"
  | "delete"
  | "head"
  | "options";

/** True when `value` is a non-null, non-array object. */
export function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Trim a trailing slash from a base URL so joining is predictable. */
export function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

/** Join a base URL and an API path without doubling or dropping slashes. */
export function joinUrl(baseUrl: string, path: string): string {
  const base = trimTrailingSlash(baseUrl);
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return `${base}${suffix}`;
}

/**
 * Pick the JSON media type from an OpenAPI `content` map. Falls back to any
 * media type whose name ends in `+json`, which is common for problem details.
 */
export function pickJsonMediaType(content: unknown): Record<string, any> | undefined {
  if (!isRecord(content)) return undefined;
  const direct = content["application/json"];
  if (isRecord(direct)) return direct;
  for (const [mediaType, value] of Object.entries(content)) {
    if (/(^|\/|\+)json($|;)/i.test(mediaType) && isRecord(value)) return value;
  }
  return undefined;
}

const STATUS_CODES: Record<number, GapErrorCode> = {
  401: "UNAUTHENTICATED",
  403: "FORBIDDEN",
  404: "NOT_FOUND",
  409: "CONFLICT",
  429: "RATE_LIMITED",
};

/** Map an upstream HTTP status onto a stable Gap error code. */
export function gapCodeForStatus(status: number): GapErrorCode {
  if (STATUS_CODES[status]) return STATUS_CODES[status];
  if (status >= 500) return "UNAVAILABLE";
  return "INVALID_INPUT";
}

/** Cap an upstream response body before it reaches a model or an audit log. */
export function safeBodySnippet(body: string, limit = 500): string {
  return body.slice(0, Math.max(0, limit));
}

/** Turn a non-2xx upstream response into a GapError with a safe body snippet. */
export function upstreamError(status: number, statusText: string, body: string): GapError {
  const snippet = safeBodySnippet(body).trim();
  const label = statusText ? `${status} ${statusText}` : String(status);
  const code = gapCodeForStatus(status);
  return new GapError(
    snippet
      ? `Upstream request failed with ${label}: ${snippet}`
      : `Upstream request failed with ${label}.`,
    { code, status, details: { status, body: snippet } },
  );
}

/** Parse a successful upstream response as JSON when possible, else text. */
export function readUpstreamBody(body: string, contentType: string | null): unknown {
  if (body.length === 0) return undefined;
  const looksJson =
    (contentType !== null && /json/i.test(contentType)) ||
    /^[\s]*[[{]/.test(body);
  if (looksJson) {
    try {
      return JSON.parse(body) as unknown;
    } catch {
      return body;
    }
  }
  return body;
}

/** An AbortSignal that may be absent when execute is called outside the pipeline. */
export function signalFrom(ctx: { signal?: AbortSignal } | undefined): AbortSignal | undefined {
  return ctx?.signal;
}

/** Risk and confirmation policy shared by imported mutations. */
export function riskForMethod(method: ImportedHttpMethod): {
  risk: RiskLevel;
  confirm?: true;
} {
  switch (method) {
    case "delete":
      return { risk: "high", confirm: true };
    case "post":
    case "put":
    case "patch":
      return { risk: "medium" };
    default:
      return { risk: "low" };
  }
}

/** Serialize one query value, expanding arrays into repeated parameters. */
export function appendQueryValue(
  query: URLSearchParams,
  name: string,
  value: unknown,
): void {
  if (value === undefined || value === null) return;
  if (Array.isArray(value)) {
    for (const item of value) appendQueryValue(query, name, item);
    return;
  }
  if (typeof value === "object") {
    query.append(name, JSON.stringify(value));
    return;
  }
  query.append(name, String(value));
}

/** Human-readable duration used in error and description strings. */
export function describeMethod(method: ImportedHttpMethod): string {
  return method.toUpperCase();
}
