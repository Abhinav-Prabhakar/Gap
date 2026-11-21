import { describe, expect, it, vi } from "vitest";
import type { Principal } from "gapmcp-core";
import { apiKeyAuth } from "../src/index";

const KEY = "sk_test_123456789";
const alice: Principal = {
  id: "user_1",
  type: "user",
  tenantId: "tenant_1",
  scopes: ["profile"],
};

function request(headers: Record<string, string> = {}): Request {
  return new Request("https://api.example.test/mcp", {
    method: "POST",
    headers,
  });
}

describe("apiKeyAuth", () => {
  it("authenticates Authorization bearer keys and merges scopes", async () => {
    const provider = apiKeyAuth({
      keys: [
        {
          key: KEY,
          principal: alice,
          scopes: ["invoices.read", "profile"],
        },
      ],
    });

    const result = await provider.authenticate(
      request({ authorization: `Bearer ${KEY}` }),
    );

    expect(result).not.toBeNull();
    expect(result?.principal).toEqual({
      ...alice,
      scopes: ["profile", "invoices.read"],
    });
    expect(result?.scopes).toEqual(["profile", "invoices.read"]);
    expect(result?.token).toBe(KEY);
    expect(result?.clientId).toBe("user_1");
  });

  it("authenticates X-API-Key headers", async () => {
    const provider = apiKeyAuth({
      keys: [{ key: KEY, principal: { id: "plain_user" } }],
    });

    const result = await provider.authenticate(request({ "x-api-key": KEY }));

    expect(result?.principal).toEqual({ id: "plain_user" });
    expect(result?.scopes).toBeUndefined();
  });

  it("falls through a wrong bearer key to a valid X-API-Key", async () => {
    const provider = apiKeyAuth({
      keys: [{ key: KEY, principal: alice }],
    });

    const result = await provider.authenticate(
      request({ authorization: "Bearer wrong", "x-api-key": KEY }),
    );

    expect(result?.principal.id).toBe("user_1");
  });

  it("rejects wrong, missing, malformed and empty keys", async () => {
    const provider = apiKeyAuth({
      keys: [{ key: KEY, principal: alice }],
    });

    expect(await provider.authenticate(request())).toBeNull();
    expect(
      await provider.authenticate(request({ authorization: "Bearer wrong" })),
    ).toBeNull();
    expect(
      await provider.authenticate(request({ authorization: "Basic abc" })),
    ).toBeNull();
    expect(
      await provider.authenticate(request({ authorization: "Bearer " })),
    ).toBeNull();
    expect(
      await provider.authenticate(request({ "x-api-key": "   " })),
    ).toBeNull();
  });

  it("honours an explicit header restriction", async () => {
    const provider = apiKeyAuth({
      keys: [{ key: KEY, principal: alice }],
      header: "x-api-key",
    });

    expect(
      await provider.authenticate(request({ authorization: `Bearer ${KEY}` })),
    ).toBeNull();
    expect(
      (await provider.authenticate(request({ "x-api-key": KEY })))?.principal
        .id,
    ).toBe("user_1");

    const authorizationOnly = apiKeyAuth({
      keys: [{ key: KEY, principal: alice }],
      header: "authorization",
    });
    expect(
      await authorizationOnly.authenticate(request({ "x-api-key": KEY })),
    ).toBeNull();
  });

  it("uses a synchronous or asynchronous resolver", async () => {
    const resolver = vi.fn((req: Request) =>
      req.headers.get("x-api-key") === KEY
        ? {
            key: KEY,
            principal: { id: "resolved_user" },
            scopes: ["resolved.read"],
          }
        : undefined,
    );
    const provider = apiKeyAuth({ keys: resolver });

    const result = await provider.authenticate(request({ "x-api-key": KEY }));
    expect(result?.principal.id).toBe("resolved_user");
    expect(result?.scopes).toEqual(["resolved.read"]);
    expect(resolver).toHaveBeenCalledTimes(1);

    const asyncProvider = apiKeyAuth({
      keys: async (req) =>
        req.headers.get("authorization") === `Bearer ${KEY}`
          ? { key: KEY, principal: { id: "async_user" } }
          : undefined,
    });
    expect(
      (
        await asyncProvider.authenticate(
          request({ authorization: `Bearer ${KEY}` }),
        )
      )?.principal.id,
    ).toBe("async_user");
  });

  it("does not trust a resolver record whose key does not match", async () => {
    const provider = apiKeyAuth({
      keys: () => ({ key: "different-key", principal: { id: "nobody" } }),
    });

    expect(
      await provider.authenticate(request({ authorization: `Bearer ${KEY}` })),
    ).toBeNull();
  });

  it("treats resolver failures as authentication failures", async () => {
    const provider = apiKeyAuth({
      keys: () => {
        throw new Error("database unavailable");
      },
    });

    expect(
      await provider.authenticate(request({ authorization: `Bearer ${KEY}` })),
    ).toBeNull();
  });

  it("ignores configured records with empty keys", async () => {
    const provider = apiKeyAuth({
      keys: [
        { key: "", principal: { id: "nobody" } },
        { key: KEY, principal: alice },
      ],
    });

    expect(
      await provider.authenticate(request({ authorization: "Bearer " })),
    ).toBeNull();
    expect(
      (await provider.authenticate(request({ authorization: `Bearer ${KEY}` })))
        ?.principal.id,
    ).toBe("user_1");
  });

  it("offers a bearer challenge", () => {
    const provider = apiKeyAuth({ keys: [] });
    expect(provider.challenge?.()).toBe('Bearer realm="gap"');
  });
});
