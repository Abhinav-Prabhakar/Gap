import { describe, expect, it } from "vitest";
import { GapError } from "gapmcp-core";
import type { PlannerInput } from "../src/index";
import {
  MockPlanner,
  httpPlanner,
  normalizeChatCompletionsEndpoint,
} from "../src/index";
import { tool } from "./helpers";

const tools = [
  tool("invoices.list", "Returns a paginated list of invoices for the current tenant.", {
    readOnly: true,
  }),
].map((action) => ({
  name: action.name,
  title: action.name,
  description: action.description,
  inputSchema: { type: "object", properties: {}, additionalProperties: false },
}));

const input: PlannerInput = {
  prompt: "list the invoices",
  tools,
};

function chatResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("MockPlanner", () => {
  it("consumes an array of responses in order and records calls", async () => {
    const planner = new MockPlanner([
      { tool: "invoices.list", args: { limit: 10 } },
      { tool: null, reasoning: "nothing fits" },
    ]);

    await expect(planner.choose(input)).resolves.toEqual({
      tool: "invoices.list",
      args: { limit: 10 },
    });
    expect(planner.remaining).toBe(1);
    await expect(planner.choose(input)).resolves.toEqual({
      tool: null,
      reasoning: "nothing fits",
    });
    expect(planner.remaining).toBe(0);
    expect(planner.calls).toHaveLength(2);
    expect(planner.calls[0]?.prompt).toBe("list the invoices");
  });

  it("throws a clear GapError when fixed responses run out", async () => {
    const planner = new MockPlanner([{ tool: "invoices.list" }]);
    await planner.choose(input);

    const error = await planner.choose(input).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(GapError);
    expect((error as GapError).message).toContain("ran out of responses");
    expect(planner.remaining).toBe(0);
  });

  it("supports a function planner, including async handlers", async () => {
    const planner = new MockPlanner(async (received) => ({
      tool: received.prompt.startsWith("list") ? "invoices.list" : null,
      reasoning: `tools: ${received.tools.length}`,
    }));

    await expect(planner.choose(input)).resolves.toEqual({
      tool: "invoices.list",
      reasoning: "tools: 1",
    });
    expect(planner.remaining).toBe(Number.POSITIVE_INFINITY);
    expect(planner.calls).toHaveLength(1);
  });
});

describe("httpPlanner", () => {
  it("posts an OpenAI-compatible request and parses the first tool call", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetchImpl: typeof fetch = async (request, init) => {
      calls.push({ url: String(request), init });
      return chatResponse({
        choices: [
          {
            message: {
              content: "The user wants a list.",
              tool_calls: [
                {
                  id: "call_1",
                  type: "function",
                  function: {
                    name: "invoices.list",
                    arguments: '{"limit":5}',
                  },
                },
              ],
            },
          },
        ],
      });
    };

    const planner = httpPlanner({
      endpoint: "https://api.example.com/v1/",
      model: "test-model",
      apiKey: "sk-test-key",
      headers: { "X-Org": "acme" },
      fetch: fetchImpl,
    });

    const choice = await planner.choose({ ...input, system: "Use the tools precisely." });

    expect(choice).toEqual({
      tool: "invoices.list",
      args: { limit: 5 },
      reasoning: "The user wants a list.",
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://api.example.com/v1/chat/completions");

    const headers = new Headers(calls[0]?.init?.headers);
    expect(headers.get("content-type")).toBe("application/json");
    expect(headers.get("authorization")).toBe("Bearer sk-test-key");
    expect(headers.get("x-org")).toBe("acme");

    const body = JSON.parse(String(calls[0]?.init?.body)) as {
      model: string;
      messages: Array<{ role: string; content: string }>;
      tools: Array<{ type: string; function: { name: string; parameters: unknown } }>;
      tool_choice: string;
      temperature: number;
    };
    expect(body.model).toBe("test-model");
    expect(body.messages).toEqual([
      { role: "system", content: "Use the tools precisely." },
      { role: "user", content: "list the invoices" },
    ]);
    expect(body.tools[0]?.type).toBe("function");
    expect(body.tools[0]?.function.name).toBe("invoices.list");
    expect(body.tool_choice).toBe("auto");
    expect(body.temperature).toBe(0);
  });

  it("normalizes endpoints that are already complete", async () => {
    const seen: string[] = [];
    const fetchImpl: typeof fetch = async (request) => {
      seen.push(String(request));
      return chatResponse({ choices: [] });
    };

    for (const endpoint of [
      "https://api.example.com/v1",
      "https://api.example.com/v1/",
      "https://api.example.com/v1/chat/completions",
    ]) {
      const planner = httpPlanner({ endpoint, model: "m", fetch: fetchImpl });
      await planner.choose({ prompt: "x", tools: [] });
    }

    expect(seen).toEqual([
      "https://api.example.com/v1/chat/completions",
      "https://api.example.com/v1/chat/completions",
      "https://api.example.com/v1/chat/completions",
    ]);
    expect(normalizeChatCompletionsEndpoint("https://api.example.com/v1/")).toBe(
      "https://api.example.com/v1/chat/completions",
    );
  });

  it("returns a null tool when the model makes no tool call", async () => {
    const planner = httpPlanner({
      endpoint: "https://api.example.com/v1",
      model: "m",
      fetch: async () =>
        chatResponse({
          choices: [{ message: { content: "No suitable tool is available." } }],
        }),
    });

    await expect(planner.choose({ prompt: "x", tools: [] })).resolves.toEqual({
      tool: null,
      reasoning: "No suitable tool is available.",
    });
  });

  it("falls back to the raw arguments string when JSON parsing fails", async () => {
    const planner = httpPlanner({
      endpoint: "https://api.example.com/v1",
      model: "m",
      fetch: async () =>
        chatResponse({
          choices: [
            {
              message: {
                tool_calls: [
                  {
                    function: {
                      name: "invoices.list",
                      arguments: '{"limit":',
                    },
                  },
                ],
              },
            },
          ],
        }),
    });

    const choice = await planner.choose({ prompt: "x", tools: [] });
    expect(choice.tool).toBe("invoices.list");
    expect(choice.args).toBe('{"limit":');
  });

  it("maps non-2xx responses to UNAVAILABLE without leaking the API key", async () => {
    const secret = "sk-secret-do-not-leak";
    const planner = httpPlanner({
      endpoint: "https://api.example.com/v1",
      model: "m",
      apiKey: secret,
      fetch: async () => new Response(`upstream error using ${secret}`, { status: 500 }),
    });

    const error = await planner
      .choose({ prompt: "x", tools: [] })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(GapError);
    const gap = error as GapError;
    expect(gap.code).toBe("UNAVAILABLE");
    expect(gap.status).toBe(500);
    expect(gap.message).not.toContain(secret);
    expect(JSON.stringify(gap)).not.toContain(secret);
  });

  it("maps transport failures to UNAVAILABLE without leaking the API key", async () => {
    const secret = "sk-secret-do-not-leak";
    const planner = httpPlanner({
      endpoint: "https://api.example.com/v1",
      model: "m",
      apiKey: secret,
      fetch: async () => {
        throw new Error(`connection reset while sending ${secret}`);
      },
    });

    const error = await planner
      .choose({ prompt: "x", tools: [] })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(GapError);
    expect((error as GapError).code).toBe("UNAVAILABLE");
    expect((error as GapError).message).not.toContain(secret);
    expect(JSON.stringify(error)).not.toContain(secret);
  });

  it("maps invalid JSON and malformed tool calls to UNAVAILABLE", async () => {
    const invalidJson = httpPlanner({
      endpoint: "https://api.example.com/v1",
      model: "m",
      fetch: async () => new Response("not json", { status: 200 }),
    });
    const malformed = httpPlanner({
      endpoint: "https://api.example.com/v1",
      model: "m",
      fetch: async () =>
        chatResponse({
          choices: [{ message: { tool_calls: [{ function: {} }] } }],
        }),
    });

    await expect(invalidJson.choose({ prompt: "x", tools: [] })).rejects.toMatchObject({
      code: "UNAVAILABLE",
    });
    await expect(malformed.choose({ prompt: "x", tools: [] })).rejects.toMatchObject({
      code: "UNAVAILABLE",
    });
  });
});
