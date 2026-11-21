import { describe, expect, it } from "vitest";
import { GapError } from "gapmcp-core";
import { exchangeToken } from "../src/index";

interface Captured {
  url: string;
  init: RequestInit;
}

type FetchResult = Response | (() => Response | Promise<Response>);

function mockFetch(
  response: FetchResult,
  captured: Captured[] = [],
): typeof fetch {
  return async (input, init) => {
    captured.push({ url: String(input), init: init ?? {} });
    return typeof response === "function" ? response() : response;
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const BASE_OPTIONS = {
  tokenEndpoint: "https://issuer.example.test/token",
  subjectToken: "subject-token-value",
};

describe("exchangeToken", () => {
  it("posts an RFC 8693 form and maps the response to camelCase", async () => {
    const captured: Captured[] = [];
    const result = await exchangeToken({
      ...BASE_OPTIONS,
      audience: "https://api.example.test/mcp",
      scope: ["invoices.read", "invoices.write"],
      clientId: "client_1",
      fetch: mockFetch(
        jsonResponse({
          access_token: "exchanged-token",
          token_type: "Bearer",
          expires_in: 300,
          scope: "invoices.read invoices.write",
        }),
        captured,
      ),
    });

    expect(result).toEqual({
      accessToken: "exchanged-token",
      expiresIn: 300,
      tokenType: "Bearer",
      scope: "invoices.read invoices.write",
    });

    expect(captured).toHaveLength(1);
    const call = captured[0]!;
    expect(call.url).toBe("https://issuer.example.test/token");
    expect(call.init.method).toBe("POST");
    const headers = new Headers(call.init.headers);
    expect(headers.get("content-type")).toBe(
      "application/x-www-form-urlencoded",
    );
    expect(headers.get("accept")).toBe("application/json");
    expect(headers.get("authorization")).toBeNull();

    const body = new URLSearchParams(String(call.init.body));
    expect(body.get("grant_type")).toBe(
      "urn:ietf:params:oauth:grant-type:token-exchange",
    );
    expect(body.get("subject_token")).toBe("subject-token-value");
    expect(body.get("subject_token_type")).toBe(
      "urn:ietf:params:oauth:token-type:access_token",
    );
    expect(body.get("audience")).toBe("https://api.example.test/mcp");
    expect(body.get("scope")).toBe("invoices.read invoices.write");
    expect(body.get("client_id")).toBe("client_1");
    expect(body.has("client_secret")).toBe(false);
  });

  it("uses Basic client authentication when a secret is present", async () => {
    const captured: Captured[] = [];
    const result = await exchangeToken({
      ...BASE_OPTIONS,
      clientId: "client_1",
      clientSecret: "super-secret",
      fetch: mockFetch(
        jsonResponse({ access_token: "new-token", token_type: "Bearer" }),
        captured,
      ),
    });

    expect(result.accessToken).toBe("new-token");

    const call = captured[0]!;
    const headers = new Headers(call.init.headers);
    expect(headers.get("authorization")).toBe(
      `Basic ${Buffer.from("client_1:super-secret").toString("base64")}`,
    );
    const body = new URLSearchParams(String(call.init.body));
    expect(body.has("client_id")).toBe(false);
    expect(body.has("client_secret")).toBe(false);
  });

  it("supports a subject token type override, default token type and numeric strings", async () => {
    const captured: Captured[] = [];
    const result = await exchangeToken({
      ...BASE_OPTIONS,
      subjectTokenType: "urn:example:custom",
      fetch: mockFetch(
        jsonResponse({
          access_token: "new-token",
          expires_in: "120",
        }),
        captured,
      ),
    });

    expect(result).toEqual({
      accessToken: "new-token",
      expiresIn: 120,
      tokenType: "Bearer",
    });
    expect(
      new URLSearchParams(String(captured[0]!.init.body)).get(
        "subject_token_type",
      ),
    ).toBe("urn:example:custom");
  });

  it("raises UNAVAILABLE with safe details on non-2xx responses", async () => {
    const error = await exchangeToken({
      ...BASE_OPTIONS,
      fetch: mockFetch(
        jsonResponse(
          {
            error: "invalid_grant",
            error_description: "Subject token expired.",
            access_token: "must-not-leak",
          },
          400,
        ),
      ),
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(GapError);
    const gap = error as GapError;
    expect(gap.code).toBe("UNAVAILABLE");
    expect(gap.status).toBe(503);
    expect(gap.details).toEqual({
      status: 400,
      error: "invalid_grant",
      errorDescription: "Subject token expired.",
    });
    expect(JSON.stringify(gap.details)).not.toContain("must-not-leak");
    expect(gap.message).not.toContain("subject-token-value");
  });

  it("redacts subject tokens and client secrets from error details", async () => {
    const error = await exchangeToken({
      ...BASE_OPTIONS,
      clientId: "client_1",
      clientSecret: "super-secret",
      fetch: mockFetch(
        jsonResponse(
          {
            error: "invalid_request",
            error_description:
              "subject-token-value was rejected for super-secret",
          },
          400,
        ),
      ),
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(GapError);
    const details = JSON.stringify((error as GapError).details);
    expect(details).not.toContain("subject-token-value");
    expect(details).not.toContain("super-secret");
    expect(details).toContain("[REDACTED]");
  });

  it("raises UNAVAILABLE for network errors", async () => {
    const fetchImpl: typeof fetch = async () => {
      throw new Error("network down");
    };

    const error = await exchangeToken({
      ...BASE_OPTIONS,
      fetch: fetchImpl,
    }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(GapError);
    expect((error as GapError).code).toBe("UNAVAILABLE");
    expect((error as GapError).message).not.toContain("subject-token-value");
  });

  it("raises UNAVAILABLE for malformed successful responses", async () => {
    const missingToken = await exchangeToken({
      ...BASE_OPTIONS,
      fetch: mockFetch(jsonResponse({ token_type: "Bearer" })),
    }).catch((caught: unknown) => caught);
    expect(missingToken).toBeInstanceOf(GapError);
    expect((missingToken as GapError).code).toBe("UNAVAILABLE");

    const invalidJson = await exchangeToken({
      ...BASE_OPTIONS,
      fetch: mockFetch(new Response("not json", { status: 200 })),
    }).catch((caught: unknown) => caught);
    expect(invalidJson).toBeInstanceOf(GapError);
    expect((invalidJson as GapError).code).toBe("UNAVAILABLE");

    const arrayBody = await exchangeToken({
      ...BASE_OPTIONS,
      fetch: mockFetch(jsonResponse([])),
    }).catch((caught: unknown) => caught);
    expect(arrayBody).toBeInstanceOf(GapError);
    expect((arrayBody as GapError).code).toBe("UNAVAILABLE");
  });

  it("rejects missing required options", async () => {
    await expect(
      exchangeToken({ ...BASE_OPTIONS, tokenEndpoint: "" }),
    ).rejects.toBeInstanceOf(GapError);
    await expect(
      exchangeToken({ ...BASE_OPTIONS, subjectToken: "  " }),
    ).rejects.toBeInstanceOf(GapError);
  });
});
