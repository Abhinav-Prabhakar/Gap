import { describe, expect, it } from "vitest";
import { bearerChallenge, protectedResourceMetadata } from "../src/index";

describe("protectedResourceMetadata", () => {
  it("builds an RFC 9728 document", () => {
    expect(
      protectedResourceMetadata({
        resource: "https://api.example.test/mcp",
        authorizationServers: ["https://issuer.example.test"],
        scopesSupported: ["invoices.read", "invoices.write"],
      }),
    ).toEqual({
      resource: "https://api.example.test/mcp",
      authorization_servers: ["https://issuer.example.test"],
      scopes_supported: ["invoices.read", "invoices.write"],
      bearer_methods_supported: ["header"],
      resource_documentation: "https://api.example.test/mcp",
    });
  });

  it("defaults optional fields and supports a documentation override", () => {
    const minimal = protectedResourceMetadata({
      resource: "https://api.example.test/mcp",
      authorizationServers: [],
    });
    expect(minimal.scopes_supported).toEqual([]);
    expect(minimal.bearer_methods_supported).toEqual(["header"]);
    expect(minimal.resource_documentation).toBe("https://api.example.test/mcp");

    const documented = protectedResourceMetadata({
      resource: "https://api.example.test/mcp",
      authorizationServers: ["https://issuer.example.test"],
      scopesSupported: ["read"],
      resourceDocumentation: "https://docs.example.test/mcp",
    });
    expect(documented.resource_documentation).toBe(
      "https://docs.example.test/mcp",
    );
  });
});

describe("bearerChallenge", () => {
  it("defaults to the gap realm", () => {
    expect(bearerChallenge()).toBe('Bearer realm="gap"');
  });

  it("includes error and resource metadata parameters", () => {
    expect(
      bearerChallenge({
        error: "invalid_token",
        resourceMetadataUrl:
          "https://api.example.test/.well-known/oauth-protected-resource",
      }),
    ).toBe(
      'Bearer realm="gap", error="invalid_token", resource_metadata="https://api.example.test/.well-known/oauth-protected-resource"',
    );
  });

  it("quotes and escapes parameter values", () => {
    expect(
      bearerChallenge({
        realm: 'api "prod" \\ edge',
        error: "insufficient_scope",
      }),
    ).toBe(
      'Bearer realm="api \\"prod\\" \\\\ edge", error="insufficient_scope"',
    );
  });

  it("strips control characters that could inject headers", () => {
    const challenge = bearerChallenge({
      realm: "gap\r\nX-Injected: yes",
      error: "invalid_token",
    });
    expect(challenge).not.toContain("\r");
    expect(challenge).not.toContain("\n");
    expect(challenge).toBe(
      'Bearer realm="gapX-Injected: yes", error="invalid_token"',
    );
  });
});
