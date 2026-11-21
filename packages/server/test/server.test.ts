import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { ActionRegistry, defineAction, type AuthProvider } from "gapmcp-core";
import { GapPolicy, parsePolicy } from "gapmcp-policy";
import { MemoryAuditLog } from "gapmcp-auth";
import { MemoryApprovalStore, createGapServer, type GapServer, type GapServerOptions } from "../src/index";

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

interface Session {
  rpc(method: string, params?: unknown): Promise<RpcResult>;
  notify(method: string): Promise<void>;
  server: GapServer;
  close(): Promise<void>;
}

interface RpcResult {
  result?: Record<string, unknown>;
  error?: { code: number; message: string; data?: unknown };
}

function parseBody(contentType: string | null, body: string): unknown {
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

async function connect(options: GapServerOptions, token?: string): Promise<Session> {
  const server = createGapServer(options);
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (token) headers.authorization = `Bearer ${token}`;

  const post = async (payload: unknown) => {
    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        method: "POST",
        headers: { ...headers, ...(sessionId ? { "mcp-session-id": sessionId } : {}) },
        body: JSON.stringify(payload),
      }),
    );
    const text = await response.text();
    return { response, text, parsed: parseBody(response.headers.get("content-type"), text) };
  };

  let sessionId: string | undefined;
  const initialized = await post({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "gapmcp-server-test", version: "0.1.0" },
    },
  });
  sessionId = initialized.response.headers.get("mcp-session-id") ?? undefined;

  return {
    server,
    async rpc(method, params) {
      const { parsed, response, text } = await post({ jsonrpc: "2.0", id: 2, method, params: params ?? {} });
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${text}`);
      return (parsed ?? {}) as RpcResult;
    },
    async notify(method) {
      await post({ jsonrpc: "2.0", method });
    },
    async close() {
      if (sessionId) {
        await server
          .fetch(
            new Request("http://localhost/mcp", {
              method: "DELETE",
              headers: { ...headers, "mcp-session-id": sessionId },
            }),
          )
          .catch(() => undefined);
      }
      await server.close();
    },
  };
}

async function callTool(
  session: Session,
  name: string,
  args: Record<string, unknown> = {},
  meta?: Record<string, unknown>,
): Promise<{ isError: boolean; text: string; structured: any; raw: any }> {
  const response = await session.rpc("tools/call", {
    name,
    arguments: args,
    ...(meta ? { _meta: meta } : {}),
  });
  if (response.error) throw new Error(`tools/call failed: ${response.error.message}`);
  const result = (response.result ?? {}) as {
    isError?: boolean;
    content?: Array<{ type: string; text?: string }>;
    structuredContent?: unknown;
  };
  const text = (result.content ?? [])
    .filter((item) => item.type === "text")
    .map((item) => item.text ?? "")
    .join("\n");
  return { isError: Boolean(result.isError), text, structured: result.structuredContent, raw: result };
}

async function listTools(session: Session): Promise<string[]> {
  const response = await session.rpc("tools/list");
  const tools = (response.result?.tools as Array<{ name: string }>) ?? [];
  return tools.map((tool) => tool.name);
}

const ownerAuth: AuthProvider = {
  authenticate(request) {
    if (request.headers.get("authorization") === "Bearer owner") {
      return { principal: { id: "usr_owner", scopes: ["notes:read", "notes:write", "billing:write"] } };
    }
    if (request.headers.get("authorization") === "Bearer reader") {
      return { principal: { id: "usr_reader", scopes: ["notes:read"] } };
    }
    return null;
  },
};

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

const notes = new Map<string, string>();
const counters = { created: 0, undone: 0, tasks: 0 };
let lastReceiptId: string | undefined;

const listNotes = defineAction({
  name: "notes.list",
  description: "List notes. Read-only and safe to call repeatedly.",
  input: z.object({}),
  output: z.object({ notes: z.array(z.string()) }),
  scopes: ["notes:read"],
  execute: () => ({ notes: [...notes.keys()] }),
});

const createNote = defineAction({
  name: "notes.create",
  description: "Create a note. Returns the new note id.",
  input: z.object({
    title: z.string().describe("Note title."),
    secret: z.string().optional().describe("Optional private value."),
  }),
  output: z.object({ id: z.string(), title: z.string() }),
  scopes: ["notes:write"],
  idempotent: true,
  execute: ({ title }) => {
    counters.created += 1;
    const id = `note_${notes.size + 1}`;
    notes.set(id, title);
    lastReceiptId = undefined;
    return { id, title };
  },
  undo: async (result: { id: string; title: string }) => {
    counters.undone += 1;
    notes.delete(result.id);
  },
});

const confirmNote = defineAction({
  name: "notes.confirm",
  description: "Create a note after a human confirms the call.",
  input: z.object({ title: z.string() }),
  output: z.object({ id: z.string() }),
  scopes: ["notes:write"],
  confirm: true,
  execute: ({ title }) => {
    const id = `confirmed_${notes.size + 1}`;
    notes.set(id, title);
    return { id };
  },
});

const refund = defineAction({
  name: "billing.refund",
  description: "Refund a payment. High risk and confirmation gated.",
  input: z.object({ amount: z.number(), reason: z.string() }),
  output: z.object({ ok: z.boolean() }),
  scopes: ["billing:write"],
  risk: "high" as const,
  execute: () => ({ ok: true }),
});

const exportNotes = defineAction({
  name: "notes.export",
  description: "Export every note as a background task.",
  input: z.object({}),
  output: z.object({ exported: z.number() }),
  scopes: ["notes:read"],
  task: true,
  execute: async () => {
    counters.tasks += 1;
    await new Promise((resolve) => setTimeout(resolve, 20));
    return { exported: notes.size };
  },
});

const uiNote = defineAction({
  name: "notes.ui",
  description: "Create a note from the semantic UI binding.",
  input: z.object({ title: z.string() }),
  output: z.object({ id: z.string() }),
  scopes: ["notes:write"],
  ui: {
    route: "/notes/new",
    action: "notes.ui",
    fields: { title: "#title" },
    submit: "#create",
  },
  execute: ({ title }) => ({ id: `ui_${title}` }),
});

function registry(): ActionRegistry {
  return new ActionRegistry([listNotes, createNote, confirmNote, refund, exportNotes, uiNote]);
}

function baseOptions(overrides: Partial<GapServerOptions> = {}): GapServerOptions {
  return {
    registry: registry(),
    auth: ownerAuth,
    ...overrides,
  };
}

const sessions: Session[] = [];

async function session(options: GapServerOptions = baseOptions(), token = "owner"): Promise<Session> {
  const created = await connect(options, token);
  sessions.push(created);
  return created;
}

afterEach(async () => {
  await Promise.allSettled(sessions.splice(0).map((item) => item.close()));
  notes.clear();
  counters.created = 0;
  counters.undone = 0;
  counters.tasks = 0;
});

// ---------------------------------------------------------------------------
// Transport and discovery
// ---------------------------------------------------------------------------

describe("server transport", () => {
  it("serves an unauthenticated health document", async () => {
    const server = createGapServer(baseOptions());
    const response = await server.fetch(new Request("http://localhost/health"));
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.status).toBe("ok");
    expect(body.actions).toBe(6);
    await server.close();
  });

  it("rejects unauthenticated MCP requests when auth is configured", async () => {
    const server = createGapServer(baseOptions());
    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
      }),
    );
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBeTruthy();
    await server.close();
  });

  it("serves RFC 9728 protected-resource metadata", async () => {
    const server = createGapServer(
      baseOptions({
        baseUrl: "https://api.example.com",
        auth: {
          ...ownerAuth,
          protectedResourceMetadata: () => ({
            resource: "https://api.example.com/mcp",
            authorization_servers: ["https://auth.example.com"],
            bearer_methods_supported: ["header"],
          }),
        },
      }),
    );
    const response = await server.fetch(
      new Request("http://localhost/.well-known/oauth-protected-resource"),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.resource).toBe("https://api.example.com/mcp");
    await server.close();
  });

  it("answers CORS preflight and returns 404 for unknown routes", async () => {
    const server = createGapServer(baseOptions());
    const preflight = await server.fetch(
      new Request("http://localhost/mcp", {
        method: "OPTIONS",
        headers: { origin: "https://app.example.com", "access-control-request-method": "POST" },
      }),
    );
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-origin")).toBeTruthy();
    const missing = await server.fetch(new Request("http://localhost/nope"));
    expect(missing.status).toBe(404);
    await server.close();
  });

  it("filters discovery by scope and exposes meta-tools", async () => {
    const reader = await session(baseOptions(), "reader");
    const names = await listTools(reader);
    expect(names).toContain("notes.list");
    expect(names).not.toContain("notes.create");
    expect(names).not.toContain("notes.confirm");
    expect(names).toContain("gap.receipts.get");
    expect(names).toContain("gap.tasks.get");
    expect(names).not.toContain("gap.undo");

    const owner = await session();
    expect(await listTools(owner)).toContain("gap.undo");
  });

  it("supports stateless request handling without a session", async () => {
    const server = createGapServer(baseOptions({ sessionMode: "stateless" }));
    const response = await server.fetch(
      new Request("http://localhost/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: "Bearer owner",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "test", version: "1" },
          },
        }),
      }),
    );
    expect(response.status).toBe(200);
    await server.close();
  });
});

// ---------------------------------------------------------------------------
// Calls, validation and policy
// ---------------------------------------------------------------------------

describe("call pipeline", () => {
  it("executes an action and returns structured content with a receipt", async () => {
    const owner = await session();
    const result = await callTool(owner, "notes.create", { title: "First" });
    expect(result.isError).toBe(false);
    expect(result.structured).toMatchObject({ id: "note_1", title: "First" });
    expect(result.text).toContain("note_1");
    const meta = result.raw._meta as { "gap/receipt": { id: string; action: string; undoable: boolean } };
    expect(meta["gap/receipt"].id).toMatch(/^rcpt_/);
    expect(meta["gap/receipt"]).toMatchObject({ action: "notes.create", undoable: true });
  });

  it("returns an MCP tool error for invalid input", async () => {
    const owner = await session();
    const result = await callTool(owner, "notes.create", { title: 4 });
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "INVALID_INPUT" } });
  });

  it("returns an error for an unknown tool", async () => {
    const owner = await session();
    const result = await callTool(owner, "notes.nope");
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "NOT_FOUND" } });
  });

  it("rejects a call the principal lacks scopes for", async () => {
    const reader = await session(baseOptions(), "reader");
    const result = await callTool(reader, "notes.create", { title: "Nope" });
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "FORBIDDEN" } });
    expect(counters.created).toBe(0);
  });

  it("enforces a policy deny", async () => {
    const owner = await session(
      baseOptions({
        policy: new GapPolicy(
          parsePolicy(
            JSON.stringify({ version: 1, rules: [{ tools: ["billing.*"], deny: true }] }),
          ),
        ),
      }),
    );
    const result = await callTool(owner, "billing.refund", { amount: 20, reason: "test" });
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "POLICY_DENIED" } });
  });

  it("applies amount limits from policy", async () => {
    const owner = await session(
      baseOptions({
        policy: new GapPolicy(
          parsePolicy(
            JSON.stringify({
              version: 1,
              rules: [{ tools: ["billing.refund"], maxAmount: 50, amountPaths: ["amount"] }],
            }),
          ),
        ),
      }),
    );
    const denied = await callTool(owner, "billing.refund", { amount: 500, reason: "too much" });
    expect(denied.isError).toBe(true);
    expect(denied.text).toMatch(/limit|amount/i);
  });

  it("runs a policy dry-run without executing the action", async () => {
    const owner = await session(
      baseOptions({
        policy: new GapPolicy(
          parsePolicy(JSON.stringify({ version: 1, rules: [{ tools: ["notes.create"], dryRun: true }] })),
        ),
      }),
    );
    const result = await callTool(owner, "notes.create", { title: "Dry" });
    expect(result.isError).toBe(false);
    expect(result.structured).toMatchObject({ status: "dry_run", action: "notes.create" });
    expect(counters.created).toBe(0);
  });

  it("redacts configured result paths", async () => {
    const owner = await session(baseOptions({ redact: ["secret"] }));
    const result = await callTool(owner, "notes.create", { title: "Redacted", secret: "hunter2" });
    expect(result.isError).toBe(false);
    expect(result.structured.secret).toBeUndefined();
    expect(JSON.stringify(result.structured)).not.toContain("hunter2");
  });
});

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

describe("approvals", () => {
  it("parks a confirm action until a human approves, then executes on retry", async () => {
    const store = new MemoryApprovalStore();
    const owner = await session(baseOptions({ approvalStore: store }));
    const pending = await callTool(owner, "notes.confirm", { title: "Approved" });
    expect(pending.isError).toBe(false);
    expect(pending.structured).toMatchObject({ status: "approval_required", action: "notes.confirm" });
    expect(pending.text).toMatch(/Approval ID/);
    const approvalId = pending.structured.approvalId as string;
    expect(store.get(approvalId)?.status).toBe("pending");

    await store.approve(approvalId, { actor: "human" });
    const retried = await callTool(owner, "notes.confirm", { title: "Approved" });
    expect(retried.isError).toBe(false);
    expect(retried.structured).toMatchObject({ id: expect.stringMatching(/^confirmed_/) });
    expect(store.get(approvalId)?.status).toBe("consumed");
  });

  it("rejects an approved call whose arguments changed", async () => {
    const store = new MemoryApprovalStore();
    const owner = await session(baseOptions({ approvalStore: store }));
    const pending = await callTool(owner, "notes.confirm", { title: "Original" });
    await store.approve(pending.structured.approvalId, { actor: "human" });
    const changed = await callTool(owner, "notes.confirm", { title: "Swapped" });
    expect(changed.structured).toMatchObject({ status: "approval_required" });
    expect(changed.structured.approvalId).not.toBe(pending.structured.approvalId);
  });

  it("reports a denied approval", async () => {
    const store = new MemoryApprovalStore();
    const owner = await session(baseOptions({ approvalStore: store }));
    const pending = await callTool(owner, "notes.confirm", { title: "Denied" });
    await store.deny(pending.structured.approvalId, { actor: "human", reason: "no" });
    const retried = await callTool(owner, "notes.confirm", { title: "Denied" });
    expect(retried.isError).toBe(true);
    expect(retried.structured).toMatchObject({ gapError: { code: "APPROVAL_REQUIRED" } });
    expect(retried.text).toMatch(/denied/i);
  });
});

// ---------------------------------------------------------------------------
// Rate limits and idempotency
// ---------------------------------------------------------------------------

describe("rate limits and idempotency", () => {
  it("rate limits per principal without affecting other principals", async () => {
    const owner = await session(baseOptions({ rateLimit: { limit: 2, windowMs: 60_000 } }));
    await callTool(owner, "notes.list");
    await callTool(owner, "notes.list");
    const limited = await callTool(owner, "notes.list");
    expect(limited.isError).toBe(true);
    expect(limited.structured).toMatchObject({ gapError: { code: "RATE_LIMITED" } });
    expect(limited.text).toMatch(/rate/i);

    const reader = await session(
      baseOptions({ rateLimit: { limit: 2, windowMs: 60_000 } }),
      "reader",
    );
    const allowed = await callTool(reader, "notes.list");
    expect(allowed.isError).toBe(false);
  });

  it("replays an idempotent action once for identical arguments", async () => {
    const owner = await session();
    const first = await callTool(owner, "notes.create", { title: "Once" });
    const second = await callTool(owner, "notes.create", { title: "Once" });
    expect(second.structured).toEqual(first.structured);
    expect(counters.created).toBe(1);
  });

  it("honours an explicit idempotency key", async () => {
    const owner = await session();
    const first = await callTool(owner, "notes.create", { title: "Keyed" }, { idempotencyKey: "key-1" });
    const second = await callTool(owner, "notes.create", { title: "Keyed" }, { idempotencyKey: "key-1" });
    expect(second.structured).toEqual(first.structured);
    expect(counters.created).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Receipts, undo, tasks and handoff
// ---------------------------------------------------------------------------

describe("receipts and undo", () => {
  it("reads a receipt and runs the action's inverse", async () => {
    const owner = await session();
    const created = await callTool(owner, "notes.create", { title: "Undo me" });
    const receiptId = (created.raw._meta as { "gap/receipt": { id: string } })["gap/receipt"].id;

    const receipt = await callTool(owner, "gap.receipts.get", { receiptId });
    expect(receipt.isError).toBe(false);
    expect(receipt.structured).toMatchObject({
      receipt: { id: receiptId, action: "notes.create", undoable: true },
      result: { id: "note_1", title: "Undo me" },
    });
    expect(receipt.structured.receipt.resultHash).toMatch(/^[a-f0-9]{64}$/);

    const undone = await callTool(owner, "gap.undo", { receiptId });
    expect(undone.isError).toBe(false);
    expect(counters.undone).toBe(1);
    expect(notes.size).toBe(0);

    const again = await callTool(owner, "gap.undo", { receiptId });
    expect(again.isError).toBe(true);
    expect(again.structured).toMatchObject({ gapError: { code: "CONFLICT" } });
  });

  it("does not expose another principal's receipt", async () => {
    const owner = await session();
    const created = await callTool(owner, "notes.create", { title: "Private" });
    const receiptId = (created.raw._meta as { "gap/receipt": { id: string } })["gap/receipt"].id;

    const reader = await session(baseOptions(), "reader");
    const result = await callTool(reader, "gap.receipts.get", { receiptId });
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "NOT_FOUND" } });
  });
});

describe("background tasks", () => {
  it("starts a task and returns its result through gap.tasks.get", async () => {
    const owner = await session();
    const started = await callTool(owner, "notes.export");
    expect(started.isError).toBe(false);
    expect(started.structured).toMatchObject({ status: "working", action: "notes.export" });
    const taskId = started.structured.taskId as string;

    let task: any;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const polled = await callTool(owner, "gap.tasks.get", { taskId });
      task = polled.structured;
      if (task.status !== "working") break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(task.status).toBe("completed");
    expect(task.result).toEqual({ exported: 0 });
    expect(counters.tasks).toBe(1);
  });

  it("cancels a running task", async () => {
    const slow = defineAction({
      name: "notes.slow",
      description: "Sleep until cancelled.",
      input: z.object({}),
      scopes: ["notes:read"],
      task: true,
      execute: async (_input, ctx) => {
        await new Promise((resolve, reject) => {
          const timer = setTimeout(resolve, 2_000);
          ctx.signal.addEventListener("abort", () => {
            clearTimeout(timer);
            reject(new Error("aborted"));
          });
        });
        return { done: true };
      },
    });
    const owner = await session(baseOptions({ registry: new ActionRegistry([slow]) }));
    const started = await callTool(owner, "notes.slow");
    const taskId = started.structured.taskId as string;
    const cancelled = await callTool(owner, "gap.tasks.cancel", { taskId });
    expect(cancelled.isError).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 20));
    const polled = await callTool(owner, "gap.tasks.get", { taskId });
    expect(polled.structured.status).toBe("cancelled");
  });
});

describe("handoff", () => {
  it("creates a signed link for an action with a UI binding", async () => {
    const owner = await session(baseOptions({ handoffSecret: "secret", baseUrl: "https://app.example.com" }));
    const result = await callTool(owner, "gap.handoff", { action: "notes.ui", args: { title: "Hello" } });
    expect(result.isError).toBe(false);
    expect(result.structured.url).toMatch(/^https:\/\/app\.example\.com\/notes\/new\?gap_state=/);
    expect(result.structured.action).toBe("notes.ui");
  });

  it("rejects handoff for an action without a UI binding", async () => {
    const owner = await session(baseOptions({ handoffSecret: "secret" }));
    const result = await callTool(owner, "gap.handoff", { action: "notes.create", args: { title: "x" } });
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "INVALID_INPUT" } });
  });
});

// ---------------------------------------------------------------------------
// Audit, tracing and call store
// ---------------------------------------------------------------------------

describe("observability", () => {
  it("records every decision in the audit sink", async () => {
    const audit = new MemoryAuditLog();
    const owner = await session(
      baseOptions({
        audit,
        policy: new GapPolicy(
          parsePolicy(JSON.stringify({ version: 1, rules: [{ tools: ["billing.*"], deny: true }] })),
        ),
      }),
    );
    await callTool(owner, "notes.list");
    await callTool(owner, "billing.refund", { amount: 1, reason: "x" });
    await expect(callTool(owner, "notes.create", { title: 4 })).resolves.toBeDefined();

    const events = audit.list();
    expect(events.some((event) => event.decision === "allowed" && event.action === "notes.list")).toBe(true);
    expect(events.some((event) => event.decision === "denied" && event.action === "billing.refund")).toBe(true);
    expect(events.some((event) => event.decision === "error" && event.action === "notes.create")).toBe(true);
    for (const event of events) {
      expect(event.argsHash).toMatch(/^[a-f0-9]{64}$/);
      expect(JSON.stringify(event)).not.toContain("hunter2");
    }
  });

  it("keeps an inspector-friendly call log", async () => {
    const owner = await session();
    await callTool(owner, "notes.list");
    await callTool(owner, "notes.create", { title: "Logged" });
    const records = owner.server.calls.list();
    expect(records).toHaveLength(2);
    expect(records[0]?.action).toBe("notes.create");
    expect(records[0]?.status).toBe("success");
    expect(records[0]?.principalId).toBe("usr_owner");
    expect(owner.server.calls.list({ action: "notes.list" })).toHaveLength(1);
    owner.server.calls.clear();
    expect(owner.server.calls.list()).toEqual([]);
  });
});
