import { quoteHeaderValue } from "./util";

/** Options for an RFC 9728 protected resource metadata document. */
export interface ProtectedResourceMetadataOptions {
  /** Canonical URL of the protected resource (the MCP endpoint). */
  resource: string;
  /** Issuer URLs of authorization servers that can mint tokens for this resource. */
  authorizationServers: string[];
  /** Scopes the resource understands. */
  scopesSupported?: string[];
  /**
   * Human-readable documentation URL. Defaults to `resource`, which is a useful
   * starting point for clients that discover the endpoint.
   */
  resourceDocumentation?: string;
}

/**
 * Build the JSON body for `/.well-known/oauth-protected-resource` as defined by
 * RFC 9728. Bearer tokens are accepted in the `Authorization` header only.
 */
export function protectedResourceMetadata(
  options: ProtectedResourceMetadataOptions,
): Record<string, unknown> {
  return {
    resource: options.resource,
    authorization_servers: [...options.authorizationServers],
    scopes_supported: [...(options.scopesSupported ?? [])],
    bearer_methods_supported: ["header"],
    resource_documentation: options.resourceDocumentation ?? options.resource,
  };
}

/** Options for a `WWW-Authenticate: Bearer` challenge. */
export interface BearerChallengeOptions {
  /** Protection space; defaults to `gap`. */
  realm?: string;
  /** RFC 6750 error code, e.g. `invalid_token` or `insufficient_scope`. */
  error?: string;
  /** RFC 9728 resource metadata URL for client discovery. */
  resourceMetadataUrl?: string;
}

/**
 * Build a correctly quoted `WWW-Authenticate: Bearer` challenge. Values are
 * escaped as HTTP quoted-strings and control characters are removed so callers
 * cannot inject extra headers.
 */
export function bearerChallenge(options: BearerChallengeOptions = {}): string {
  const parts = [`realm="${quoteHeaderValue(options.realm ?? "gap")}"`];
  if (options.error !== undefined) {
    parts.push(`error="${quoteHeaderValue(options.error)}"`);
  }
  if (options.resourceMetadataUrl !== undefined) {
    parts.push(
      `resource_metadata="${quoteHeaderValue(options.resourceMetadataUrl)}"`,
    );
  }
  return `Bearer ${parts.join(", ")}`;
}
