import { describe, expect, it } from "vitest";
import type { AuthProvider } from "gapmcp-core";
import { composeAuth } from "../src/index";

function request(): Request {
  return new Request("https://api.example.test/mcp");
}

describe("composeAuth", () => {
  it("returns the first non-null result in provider order", async () => {
    const calls: string[] = [];
    const first: AuthProvider = {
      authenticate: () => {
        calls.push("first");
        return null;
      },
    };
    const second: AuthProvider = {
      authenticate: async () => {
        calls.push("second");
        return { principal: { id: "second_user" } };
      },
    };
    const third: AuthProvider = {
      authenticate: () => {
        calls.push("third");
        return { principal: { id: "third_user" } };
      },
    };

    const composed = composeAuth(first, second, third);
    const result = await composed.authenticate(request());

    expect(result?.principal.id).toBe("second_user");
    expect(calls).toEqual(["first", "second"]);
  });

  it("uses the first challenge and metadata provider that defines them", () => {
    const noExtras: AuthProvider = { authenticate: () => null };
    const first: AuthProvider = {
      authenticate: () => null,
      challenge: () => 'Bearer realm="first"',
      protectedResourceMetadata: () => ({ resource: "first" }),
    };
    const second: AuthProvider = {
      authenticate: () => null,
      challenge: () => 'Bearer realm="second"',
      protectedResourceMetadata: () => ({ resource: "second" }),
    };

    const composed = composeAuth(noExtras, first, second);
    expect(composed.challenge?.()).toBe('Bearer realm="first"');
    expect(composed.protectedResourceMetadata?.()).toEqual({
      resource: "first",
    });
  });

  it("omits extras when no provider defines them", async () => {
    const composed = composeAuth({ authenticate: () => null });

    expect(await composed.authenticate(request())).toBeNull();
    expect(composed.challenge).toBeUndefined();
    expect(composed.protectedResourceMetadata).toBeUndefined();
  });
});
