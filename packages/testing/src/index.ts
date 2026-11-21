import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import type { ActionContext, AnyAction, Principal } from "gapmcp-core";
import { createId, parseValue, silentLogger } from "gapmcp-core";
import type { GapServer, GapServerOptions } from "gapmcp-server";
import { createGapServer } from "gapmcp-server";

/** A principal suitable for unit tests. All scopes are granted by default. */
export function testPrincipal(overrides: Partial<Principal> = {}): Principal {
  return {
    id: "usr_test",
    type: "user",
    name: "Test User",
    email: "test@example.com",
    scopes: ["*"],
    ...overrides,
    metadata: { ...overrides.metadata },
  };
}

/** A fully-formed action context for direct action tests. */
export function testContext(overrides: Partial<ActionContext> = {}): ActionContext {
  const principal = overrides.principal ?? testPrincipal();
  return {
    principal,
    scopes: overrides.scopes ?? principal.scopes ?? [],
    tenantId: overrides.tenantId ?? principal.tenantId,
    dryRun: overrides.dryRun ?? false,
    idempotencyKey: overrides.idempotencyKey,
    approval: overrides.approval,
    signal: overrides.signal ?? AbortSignal.timeout(10_000),
    traceId: overrides.traceId ?? createId("trace"),
    logger: overrides.logger ?? silentLogger,
    ...overrides,
  };
}

/** Validate and execute an action directly, without the MCP layer. */
export async function callAction(
  action: AnyAction,
  args: unknown,
  overrides: Partial<ActionContext> = {},
): Promise<unknown> {
  const input = action.input ? parseValue(action.input, args) : args;
  return action.execute(input, testContext(overrides));
}

export interface TestServer {
  url: string;
  server: GapServer;
  close(): Promise<void>;
}

/** Start a Gap server on an ephemeral port. */
export async function startTestServer(options: GapServerOptions): Promise<TestServer> {
  const server = createGapServer(options);
  const http = createServer((req, res) => {
    void server.handleNode(req, res);
  });
  await new Promise<void>((resolve, reject) => {
    http.once("error", reject);
    http.listen(0, "127.0.0.1", () => resolve());
  });
  const { port } = http.address() as AddressInfo;
  const url = `http://127.0.0.1:${port}`;
  return {
    url,
    server,
    close: async () => {
      await new Promise<void>((resolve) => http.close(() => resolve()));
      await server.close();
    },
  };
}

interface RpcOptions {
  token?: string;
  headers?: Record<string, string>;
  sessionId?: string;
}

interface RpcResponse {
  result?: Record<string, unknown>;
  error?: { code: number; message: string; data?: unknown };
  sessionId?: string;
}

function parseSseOrJson(contentType: string | null, body: string): unknown {
  if (contentType?.includes("text/event-stream")) {
    const data = body
      .split("\n")
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .filter(Boolean);
    const last = data.at(-1);
    return last ? JSON.parse(last) : undefined;
  }
  return body ? JSON.parse(body) : undefined;
}

async function rpc(
  url: string,
  method: string,
  params: unknown,
  options: RpcOptions = {},
  id = 1,
): Promise<RpcResponse> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    ...options.headers,
  };
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  if (options.sessionId) headers["mcp-session-id"] = options.sessionId;

  const response = await fetch(`${url}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
  const body = await response.text();
  const sessionId = response.headers.get("mcp-session-id") ?? options.sessionId;
  if (!response.ok) {
    throw new Error(`MCP ${method} failed with HTTP ${response.status}: ${body.slice(0, 300)}`);
  }
  const parsed = parseSseOrJson(response.headers.get("content-type"), body) as RpcResponse | undefined;
  if (!parsed) return { sessionId };
  return { ...parsed, sessionId };
}

async function initialize(url: string, options: RpcOptions): Promise<string | undefined> {
  const response = await rpc(
    url,
    "initialize",
    {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "gapmcp-testing", version: "0.1.0" },
    },
    options,
  );
  if (response.error) throw new Error(`initialize failed: ${response.error.message}`);
  const sessionId = response.sessionId;
  if (sessionId) {
    await fetch(`${url}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-session-id": sessionId,
        ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
        ...options.headers,
      },
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    }).catch(() => undefined);
  }
  return sessionId;
}

async function closeSession(url: string, sessionId: string | undefined, options: RpcOptions): Promise<void> {
  if (!sessionId) return;
  await fetch(`${url}/mcp`, {
    method: "DELETE",
    headers: {
      "mcp-session-id": sessionId,
      ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
      ...options.headers,
    },
  }).catch(() => undefined);
}

export interface ToolCallResult {
  isError: boolean;
  text: string;
  structured?: unknown;
  raw: Record<string, unknown>;
}

/** Call a tool through the real MCP HTTP transport. */
export async function callTool(options: {
  url: string;
  name: string;
  args?: unknown;
  token?: string;
  headers?: Record<string, string>;
  meta?: Record<string, unknown>;
}): Promise<ToolCallResult> {
  const rpcOptions = { token: options.token, headers: options.headers };
  const sessionId = await initialize(options.url, rpcOptions);
  try {
    const response = await rpc(
      options.url,
      "tools/call",
      {
        name: options.name,
        arguments: options.args ?? {},
        ...(options.meta ? { _meta: options.meta } : {}),
      },
      { ...rpcOptions, sessionId },
      2,
    );
    if (response.error) {
      throw new Error(`tools/call failed: ${response.error.message}`);
    }
    const result = (response.result ?? {}) as {
      isError?: boolean;
      content?: Array<{ type: string; text?: string }>;
      structuredContent?: unknown;
    };
    const text = (result.content ?? [])
      .filter((item) => item.type === "text")
      .map((item) => item.text ?? "")
      .join("\n");
    return {
      isError: Boolean(result.isError),
      text,
      structured: result.structuredContent,
      raw: result as Record<string, unknown>,
    };
  } finally {
    await closeSession(options.url, sessionId, rpcOptions);
  }
}

/** List the tools visible to a principal through the real MCP transport. */
export async function listTools(options: {
  url: string;
  token?: string;
  headers?: Record<string, string>;
}): Promise<Array<Record<string, unknown>>> {
  const rpcOptions = { token: options.token, headers: options.headers };
  const sessionId = await initialize(options.url, rpcOptions);
  try {
    const response = await rpc(options.url, "tools/list", {}, { ...rpcOptions, sessionId }, 2);
    if (response.error) throw new Error(`tools/list failed: ${response.error.message}`);
    return ((response.result?.tools as Array<Record<string, unknown>>) ?? []).slice();
  } finally {
    await closeSession(options.url, sessionId, rpcOptions);
  }
}
