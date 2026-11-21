import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { AnyAction, ToolDescriptor } from "gapmcp-core";
import { ActionRegistry } from "gapmcp-core";
import type { GapServer, GapServerOptions } from "gapmcp-server";
import { createGapServer } from "gapmcp-server";

export interface InspectorApprovalStore {
  list(): ReadonlyArray<{ status?: string }>;
  approve(id: string): unknown;
  deny(id: string): unknown;
}

export interface InspectorOptions {
  registry: ActionRegistry;
  server?: Partial<GapServerOptions>;
  approvals?: InspectorApprovalStore;
  port?: number;
  host?: string;
  token?: string;
  open?: boolean;
}

export interface InspectorHandle {
  url: string;
  port: number;
  server: GapServer;
  close(): Promise<void>;
}

async function readBody(req: IncomingMessage, limit = 2_000_000): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > limit) throw new Error("Request body too large.");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function send(res: ServerResponse, status: number, body: string, contentType = "application/json"): void {
  res.statusCode = status;
  res.setHeader("content-type", contentType);
  res.setHeader("cache-control", "no-store");
  res.end(body);
}

function json(res: ServerResponse, status: number, value: unknown): void {
  send(res, status, JSON.stringify(value));
}

interface McpCallResult {
  isError: boolean;
  text: string;
  structured?: unknown;
  raw?: unknown;
}

async function callMcp(
  baseUrl: string,
  name: string,
  args: unknown,
  token?: string,
): Promise<McpCallResult> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (token) headers.authorization = `Bearer ${token}`;

  const initialize = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "gap-inspector", version: "0.1.0" },
      },
    }),
  });
  if (!initialize.ok) {
    throw new Error(`initialize failed (${initialize.status}): ${(await initialize.text()).slice(0, 300)}`);
  }
  const sessionId = initialize.headers.get("mcp-session-id");
  if (sessionId) {
    await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { ...headers, "mcp-session-id": sessionId },
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    }).catch(() => undefined);
  }

  const callHeaders = { ...headers, ...(sessionId ? { "mcp-session-id": sessionId } : {}) };
  const response = await fetch(`${baseUrl}/mcp`, {
    method: "POST",
    headers: callHeaders,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name, arguments: args ?? {} },
    }),
  });
  const text = await response.text();
  if (sessionId) {
    await fetch(`${baseUrl}/mcp`, {
      method: "DELETE",
      headers: callHeaders,
    }).catch(() => undefined);
  }
  if (!response.ok) throw new Error(`tools/call failed (${response.status}): ${text.slice(0, 300)}`);

  let payload: any;
  if ((response.headers.get("content-type") ?? "").includes("text/event-stream")) {
    const data = text
      .split("\n")
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .filter(Boolean)
      .at(-1);
    payload = data ? JSON.parse(data) : {};
  } else {
    payload = text ? JSON.parse(text) : {};
  }
  if (payload.error) throw new Error(`${payload.error.code}: ${payload.error.message}`);
  const result = payload.result ?? {};
  const content = (result.content ?? [])
    .filter((item: { type?: string }) => item.type === "text")
    .map((item: { text?: string }) => item.text ?? "")
    .join("\n");
  return {
    isError: Boolean(result.isError),
    text: content,
    structured: result.structuredContent,
    raw: result,
  };
}

export async function startInspector(options: InspectorOptions): Promise<InspectorHandle> {
  const port = options.port ?? 4400;
  const host = options.host ?? "127.0.0.1";
  const server = createGapServer({ ...options.server, registry: options.registry });
  let baseUrl = `http://${host}:${port}`;

  const http = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", baseUrl);

    if (url.pathname === "/mcp" || url.pathname.startsWith("/.well-known/") || url.pathname === "/health") {
      await server.handleNode(req, res);
      return;
    }

    try {
      if (req.method === "GET" && url.pathname === "/") {
        send(res, 200, INSPECTOR_HTML, "text/html; charset=utf-8");
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/meta") {
        json(res, 200, {
          name: "Gap Inspector",
          version: "0.1.0",
          tools: options.registry.size,
          calls: safeCalls(server).length,
          pendingApprovals: options.approvals?.list().filter((item) => item.status === "pending").length ?? 0,
          authRequired: Boolean(options.token),
          issues: options.registry.validate(),
        });
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/tools") {
        const descriptors = options.registry.toToolDescriptors();
        const issues = options.registry.validate();
        json(res, 200, {
          tools: descriptors.map((tool: ToolDescriptor) => {
            const action = options.registry.get(tool.name) as AnyAction | undefined;
            return {
              ...tool,
              action: action
                ? {
                    version: action.version ?? 1,
                    risk: action.risk ?? "low",
                    scopes: action.scopes ?? [],
                    idempotent: Boolean(action.idempotent),
                    task: Boolean(action.task),
                    deprecated: action.deprecated ?? false,
                    tags: action.tags ?? [],
                    ui: action.ui,
                    hasUndo: Boolean(action.undo),
                    confirm: Boolean(action.confirm),
                  }
                : undefined,
              issues: issues.filter((issue) => !issue.action || issue.action === tool.name),
            };
          }),
        });
        return;
      }

      if (req.method === "POST" && url.pathname === "/api/call") {
        const raw = await readBody(req);
        const body = JSON.parse(raw) as { name?: string; args?: unknown; argsText?: string; token?: string };
        if (!body.name) {
          json(res, 400, { error: "Tool name is required." });
          return;
        }
        let args = body.args;
        if (typeof body.argsText === "string" && body.argsText.trim()) {
          try {
            args = JSON.parse(body.argsText);
          } catch (error) {
            json(res, 400, { error: `Arguments are not valid JSON: ${(error as Error).message}` });
            return;
          }
        }
        const started = performance.now();
        try {
          const result = await callMcp(baseUrl, body.name, args, body.token ?? options.token);
          json(res, 200, { ...result, durationMs: Math.round(performance.now() - started) });
        } catch (error) {
          json(res, 200, {
            isError: true,
            text: (error as Error).message,
            durationMs: Math.round(performance.now() - started),
          });
        }
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/calls") {
        json(res, 200, { calls: safeCalls(server) });
        return;
      }

      if (req.method === "POST" && url.pathname === "/api/calls/clear") {
        const store = server.calls as unknown as { clear?: () => void };
        store.clear?.();
        json(res, 200, { ok: true });
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/approvals") {
        json(res, 200, { approvals: options.approvals?.list() ?? [] });
        return;
      }

      const approve = url.pathname.match(/^\/api\/approvals\/([^/]+)\/(approve|deny)$/);
      if (req.method === "POST" && approve) {
        if (!options.approvals) {
          json(res, 404, { error: "Approvals are not configured for this inspector." });
          return;
        }
        const [, id, action] = approve;
        try {
          const result = action === "approve" ? options.approvals.approve(id!) : options.approvals.deny(id!);
          json(res, 200, { ok: true, result });
        } catch (error) {
          json(res, 400, { error: (error as Error).message });
        }
        return;
      }

      json(res, 404, { error: "Not found." });
    } catch (error) {
      json(res, 500, { error: (error as Error).message });
    }
  });

  await new Promise<void>((resolve, reject) => {
    http.once("error", reject);
    http.listen(port, host, () => resolve());
  });
  const address = http.address() as AddressInfo;
  baseUrl = `http://${host}:${address.port}`;

  return {
    url: baseUrl,
    port: address.port,
    server,
    close: async () => {
      await new Promise<void>((resolve) => http.close(() => resolve()));
      await server.close();
    },
  };
}

function safeCalls(server: GapServer): Array<Record<string, unknown>> {
  const store = server.calls as unknown as { list?: (limit?: number) => Array<Record<string, unknown>> };
  try {
    return store.list?.(200) ?? [];
  } catch {
    return [];
  }
}

const INSPECTOR_HTML = readFileSync(new URL("./inspector.html", import.meta.url), "utf8");

export const inspectorHtml = INSPECTOR_HTML;
