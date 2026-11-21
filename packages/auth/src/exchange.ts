import { GapError } from "gapmcp-core";
import { base64Encode, encodeUtf8 } from "./crypto";
import { isRecord, nonEmptyString } from "./util";

/** RFC 8693 token-exchange grant type. */
export const TOKEN_EXCHANGE_GRANT_TYPE =
  "urn:ietf:params:oauth:grant-type:token-exchange";

/** Default subject token type for RFC 8693. */
export const ACCESS_TOKEN_TYPE =
  "urn:ietf:params:oauth:token-type:access_token";

/** Options for {@link exchangeToken}. */
export interface ExchangeTokenOptions {
  /** Authorization server token endpoint. */
  tokenEndpoint: string;
  /** Token to exchange. */
  subjectToken: string;
  /** Subject token type; defaults to an OAuth access token. */
  subjectTokenType?: string;
  /** Requested audience for the new token. */
  audience?: string;
  /** Requested scopes for the new token. */
  scope?: string[];
  /** OAuth client id. */
  clientId?: string;
  /** OAuth client secret. When present, HTTP Basic client authentication is used. */
  clientSecret?: string;
  /** Injectable fetch implementation for tests. */
  fetch?: typeof fetch;
}

/** Successful token-exchange response with camelCase fields. */
export interface TokenExchangeResult {
  accessToken: string;
  expiresIn?: number;
  tokenType: string;
  scope?: string;
}

/**
 * Exchange a subject token at an OAuth token endpoint using RFC 8693.
 *
 * The request is form encoded. When `clientSecret` is supplied, client
 * authentication uses HTTP Basic and the secret is never placed in the body.
 * Non-2xx responses raise `UNAVAILABLE` with only safe OAuth error details.
 */
export async function exchangeToken(
  options: ExchangeTokenOptions,
): Promise<TokenExchangeResult> {
  const tokenEndpoint = nonEmptyString(options.tokenEndpoint);
  const subjectToken = nonEmptyString(options.subjectToken);
  if (!tokenEndpoint) {
    throw new GapError("tokenEndpoint is required.", { code: "INVALID_INPUT" });
  }
  if (!subjectToken) {
    throw new GapError("subjectToken is required.", { code: "INVALID_INPUT" });
  }

  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new GapError("No fetch implementation is available.", {
      code: "UNAVAILABLE",
    });
  }

  const body = new URLSearchParams();
  body.set("grant_type", TOKEN_EXCHANGE_GRANT_TYPE);
  body.set("subject_token", subjectToken);
  body.set(
    "subject_token_type",
    options.subjectTokenType ?? ACCESS_TOKEN_TYPE,
  );
  if (options.audience) body.set("audience", options.audience);
  if (options.scope && options.scope.length > 0) {
    body.set("scope", options.scope.join(" "));
  }

  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded",
    accept: "application/json",
  };

  if (options.clientSecret !== undefined) {
    const credentials = `${options.clientId ?? ""}:${options.clientSecret}`;
    headers.authorization = `Basic ${base64Encode(encodeUtf8(credentials))}`;
  } else if (options.clientId) {
    body.set("client_id", options.clientId);
  }

  let response: Response;
  try {
    response = await fetchImpl(tokenEndpoint, {
      method: "POST",
      headers,
      body: body.toString(),
    });
  } catch (cause) {
    throw new GapError("Token exchange request failed.", {
      code: "UNAVAILABLE",
      cause,
    });
  }

  if (!response.ok) {
    throw new GapError(
      `Token exchange failed (HTTP ${response.status}).`,
      {
        code: "UNAVAILABLE",
        details: await readErrorDetails(response),
      },
    );
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch (cause) {
    throw new GapError("Token exchange returned invalid JSON.", {
      code: "UNAVAILABLE",
      details: { status: response.status },
      cause,
    });
  }
  if (!isRecord(payload)) {
    throw new GapError("Token exchange returned an invalid response.", {
      code: "UNAVAILABLE",
      details: { status: response.status },
    });
  }

  const accessToken = nonEmptyString(payload.access_token);
  if (!accessToken) {
    throw new GapError("Token exchange response did not include access_token.", {
      code: "UNAVAILABLE",
      details: { status: response.status },
    });
  }

  const tokenType = nonEmptyString(payload.token_type) ?? "Bearer";
  const expiresIn = readExpiresIn(payload.expires_in);
  const scope = readScope(payload.scope);

  const result: TokenExchangeResult = { accessToken, tokenType };
  if (expiresIn !== undefined) result.expiresIn = expiresIn;
  if (scope !== undefined) result.scope = scope;
  return result;
}

async function readErrorDetails(
  response: Response,
): Promise<Record<string, unknown>> {
  const details: Record<string, unknown> = { status: response.status };
  try {
    const text = await response.text();
    if (!text || text.length > 16 * 1024) return details;
    const parsed: unknown = JSON.parse(text);
    if (!isRecord(parsed)) return details;
    const error = nonEmptyString(parsed.error);
    if (error) details.error = safeText(error);
    const description = nonEmptyString(parsed.error_description);
    if (description) details.errorDescription = safeText(description);
  } catch {
    // A non-JSON error body is intentionally ignored.
  }
  return details;
}

function safeText(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 500);
}

function readExpiresIn(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function readScope(value: unknown): string | undefined {
  if (typeof value === "string") return value || undefined;
  if (Array.isArray(value)) {
    const scopes = value.filter(
      (item): item is string => typeof item === "string" && item.length > 0,
    );
    return scopes.length > 0 ? scopes.join(" ") : undefined;
  }
  return undefined;
}
