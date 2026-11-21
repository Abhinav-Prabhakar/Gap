import { describe, expect, it } from "vitest";
import { scoreAgentReadiness } from "../src/score";

function fakeFetch(routes: Record<string, { status?: number; body?: string; headers?: Record<string, string> }>): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input);
    const key = Object.keys(routes).find((candidate) => url.endsWith(candidate));
    const route = key ? routes[key]! : undefined;
    if (!route) return new Response("not found", { status: 404 });
    return new Response(route.body ?? "", {
      status: route.status ?? 200,
      headers: route.headers,
    });
  }) as typeof fetch;
}

describe("agent readiness score", () => {
  it("scores an MCP-enabled app with metadata and DOM hooks", async () => {
    const report = await scoreAgentReadiness("https://app.example.com", {
      fetch: fakeFetch({
        "/mcp": { body: JSON.stringify({ jsonrpc: "2.0", result: {} }) },
        "/.well-known/oauth-protected-resource": {
          body: JSON.stringify({ resource: "https://app.example.com/mcp", authorization_servers: [] }),
        },
        "/health": { body: "ok" },
        "/": { body: '<form data-gap-action="invoices.create"></form>', headers: { "content-type": "text/html" } },
        "/llms.txt": { body: "# App" },
      }),
    });
    expect(report.grade).toBe("A");
    expect(report.score).toBeGreaterThanOrEqual(85);
    expect(report.signals.find((signal) => signal.id === "mcp")?.passed).toBe(true);
  });

  it("scores a plain website low and explains what is missing", async () => {
    const report = await scoreAgentReadiness("https://plain.example.com", {
      fetch: fakeFetch({ "/": { body: "<h1>Hello</h1>" } }),
    });
    expect(report.grade).toBe("D");
    expect(report.signals.filter((signal) => !signal.passed).length).toBeGreaterThanOrEqual(5);
    expect(report.signals[0]?.recommendation).toMatch(/MCP/);
  });

  it("treats a 401 MCP challenge as an auth-aware endpoint", async () => {
    const report = await scoreAgentReadiness("https://secure.example.com", {
      fetch: fakeFetch({
        "/mcp": { status: 401, headers: { "www-authenticate": 'Bearer realm="app"' } },
        "/.well-known/oauth-protected-resource": { status: 401 },
      }),
    });
    expect(report.signals.find((signal) => signal.id === "mcp")?.passed).toBe(true);
    expect(report.signals.find((signal) => signal.id === "auth")?.passed).toBe(true);
  });
});
