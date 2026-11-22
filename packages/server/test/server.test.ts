import { createServer, request as httpRequest, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { z } from "zod";
import {
  ActionRegistry,
  createLogger,
  defineAction,
  hashValue,
  type ApprovalGate,
  type ApprovalGrant,
  type ApprovalRequest,
  type AuditEvent,
  type AuditSink,
  type AuthProvider,
  type IssuedApproval,
  type PolicyDecision,
  type PolicyEngine,
  type PolicyEvaluationInput,
  type Span,
  type Tracer,
} from "gapmcp-core";
import {
  MemoryApprovalStore,
  createGapServer,
  verifySignedHandoffLink,
  type CallRecord,
  type GapServer,
  type GapServerOptions,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

const logger = createLogger("silent");

const fakeAuth: AuthProvider = {
  authenticate(request) {
    const authorization = request.headers.get("authorization");
    if (authorization === "Bearer owner") {
      return {
        principal: {
          id: "usr_owner",
          type: "user",
          scopes: ["notes:read", "notes:write", "billing:write"],
        },
      };
    }
    if (authorization === "Bearer reader") {
      return {
        principal: { id: "usr_reader", type: "user", scopes: ["notes:read"] },
      };
    }
    return null;
  },
  challenge: () => 'Bearer realm="gap-test"',
  protectedResourceMetadata: () => ({
    resource: "https://api.example.com/mcp",
    authorization_servers: ["https://auth.example.com"],
    scopes_supported: ["notes:read", "notes:write", "billing:write"],
    bearer_methods_supported: ["header"],
  }),
};

class FakePolicy implements PolicyEngine {
  readonly evaluations: string[] = [];

  constructor(private readonly rules: Record<string, PolicyDecision> = {}) {}

  evaluate(input: PolicyEvaluationInput): PolicyDecision {
    this.evaluations.push(input.action.name);
    return this.rules[input.action.name] ?? { decision: "allow" };
  }
}

class FakeAudit implements AuditSink {
  readonly events: AuditEvent[] = [];

  record(event: AuditEvent): void {
    this.events.push({ ...event, scopes: event.scopes ? [...event.scopes] : undefined });
  }
}

class TestSpan implements Span {
  ended = false;
  readonly exceptions: unknown[] = [];
  readonly attributes: Record<string, unknown>;

  constructor(
    readonly name: string,
    attributes: Record<string, unknown> = {},
  ) {
    this.attributes = { ...attributes };
  }

  setAttribute(key: string, value: string | number | boolean): void {
    this.attributes[key] = value;
  }

  setAttributes(attributes: Record<string, unknown>): void {
    Object.assign(this.attributes, attributes);
  }

  recordException(error: unknown): void {
    this.exceptions.push(error);
  }

  end(): void {
    this.ended = true;
  }
}

class FakeTracer implements Tracer {
  readonly spans: TestSpan[] = [];

  startSpan(name: string, attributes: Record<string, unknown> = {}): Span {
    const span = new TestSpan(name, attributes);
    this.spans.push(span);
    return span;
  }
}

class FakeApprovalGate implements ApprovalGate {
  readonly token = "approval-token";

  async issue(request: ApprovalRequest): Promise<IssuedApproval> {
    const now = Date.now();
    return {
      token: this.token,
      grant: {
        id: "apr_token",
        action: request.action,
        argsHash: await hashValue(request.args),
        approvedBy: "human",
        issuedAt: now,
        expiresAt: now + 60_000,
      },
    };
  }

  async verify(
    token: string,
    request: Omit<ApprovalRequest, "ttlMs">,
  ): Promise<ApprovalGrant | null> {
    if (token !== this.token) return null;
    const now = Date.now();
    return {
      id: "apr_token",
      action: request.action,
      argsHash: await hashValue(request.args),
      approvedBy: "human",
      issuedAt: now,
      expiresAt: now + 60_000,
    };
  }
}

// ---------------------------------------------------------------------------
// Actions and mutable state
// ---------------------------------------------------------------------------

const state = {
  notes: new Map<string, string>(),
  created: 0,
  undone: 0,
  tasksStarted: 0,
  tasksCancelled: 0,
  cancelStarted: 0,
  slowCalls: 0,
};

function resetState(): void {
  state.notes.clear();
  state.created = 0;
  state.undone = 0;
  state.tasksStarted = 0;
  state.tasksCancelled = 0;
  state.cancelStarted = 0;
  state.slowCalls = 0;
}

const notesList = defineAction({
  name: "notes.list",
  description: "List notes. Read-only and safe to call repeatedly.",
  input: z.object({}),
  output: z.object({ notes: z.array(z.string()) }),
  scopes: ["notes:read"],
  execute: () => ({ notes: [...state.notes.keys()] }),
});

const notesCreate = defineAction({
  name: "notes.create",
  description: "Create a note. Returns the new note id.",
  input: z.object({
    title: z.string().describe("Note title."),
    secret: z.string().optional().describe("Optional private value."),
  }),
  output: z.object({ id: z.string(), title: z.string(), secret: z.string().optional() }),
  scopes: ["notes:write"],
  idempotent: true,
  execute: ({ title, secret }) => {
    state.created += 1;
    const id = `note_${state.notes.size + 1}`;
    state.notes.set(id, title);
    return { id, title, ...(secret === undefined ? {} : { secret }) };
  },
  undo: async (output) => {
    state.undone += 1;
    state.notes.delete(output.id);
  },
});

const notesSlowCreate = defineAction({
  name: "notes.slowCreate",
  description: "Create a note after a short delay. Used to test request coalescing.",
  input: z.object({ title: z.string() }),
  output: z.object({ id: z.string() }),
  scopes: ["notes:write"],
  idempotent: true,
  execute: async ({ title }) => {
    await new Promise((resolve) => setTimeout(resolve, 60));
    state.created += 1;
    const id = `slow_${state.notes.size + 1}`;
    state.notes.set(id, title);
    return { id };
  },
});

const notesConfirm = defineAction({
  name: "notes.confirm",
  description: "Create a note after a human confirms the call.",
  input: z.object({ title: z.string() }),
  output: z.object({ id: z.string() }),
  scopes: ["notes:write"],
  confirm: true,
  execute: ({ title }) => {
    const id = `confirmed_${state.notes.size + 1}`;
    state.notes.set(id, title);
    return { id };
  },
});

const notesInvalidOutput = defineAction({
  name: "notes.invalidOutput",
  description: "Return a value that violates the declared output schema.",
  input: z.object({}),
  output: z.object({ ok: z.boolean() }),
  scopes: ["notes:read"],
  execute: () => ({}) as { ok: boolean },
});

const notesSlow = defineAction({
  name: "notes.slow",
  description: "Return after a delay so the transport can be observed.",
  input: z.object({}),
  output: z.object({ ok: z.boolean() }),
  scopes: ["notes:read"],
  execute: async () => {
    state.slowCalls += 1;
    await new Promise((resolve) => setTimeout(resolve, 350));
    return { ok: true };
  },
});

const notesHang = defineAction({
  name: "notes.hang",
  description: "Wait until the call budget aborts the action.",
  input: z.object({}),
  output: z.object({ ok: z.boolean() }),
  scopes: ["notes:read"],
  timeoutMs: 60,
  execute: (_input, ctx) =>
    new Promise<{ ok: boolean }>((resolve, reject) => {
      const timer = setTimeout(() => resolve({ ok: true }), 5_000);
      ctx.signal.addEventListener(
        "abort",
        () => {
          clearTimeout(timer);
          reject(new Error("aborted"));
        },
        { once: true },
      );
    }),
});

const notesExport = defineAction({
  name: "notes.export",
  description: "Export every note as a background task.",
  input: z.object({}),
  output: z.object({ exported: z.number() }),
  scopes: ["notes:read"],
  task: true,
  execute: async () => {
    state.tasksStarted += 1;
    await new Promise((resolve) => setTimeout(resolve, 20));
    return { exported: state.notes.size };
  },
});

const notesCancelable = defineAction({
  name: "notes.cancelable",
  description: "Run until cancelled.",
  input: z.object({}),
  output: z.object({ done: z.boolean() }),
  scopes: ["notes:read"],
  task: true,
  execute: (_input, ctx) =>
    new Promise<{ done: boolean }>((resolve, reject) => {
      state.cancelStarted += 1;
      const timer = setTimeout(() => resolve({ done: true }), 5_000);
      ctx.signal.addEventListener(
        "abort",
        () => {
          clearTimeout(timer);
          state.tasksCancelled += 1;
          reject(new Error("cancelled"));
        },
        { once: true },
      );
    }),
});

const notesUi = defineAction({
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

const billingRefund = defineAction({
  name: "billing.refund",
  description: "Refund a payment. High risk and confirmation gated.",
  input: z.object({ amount: z.number(), reason: z.string() }),
  output: z.object({ ok: z.boolean() }),
  scopes: ["billing:write"],
  risk: "high",
  execute: () => ({ ok: true }),
});

const actions = [
  notesList,
  notesCreate,
  notesSlowCreate,
  notesConfirm,
  notesInvalidOutput,
  notesSlow,
  notesHang,
  notesExport,
  notesCancelable,
  notesUi,
  billingRefund,
];

function registry(): ActionRegistry {
  return new ActionRegistry(actions);
}

function baseOptions(overrides: Partial<GapServerOptions> = {}): GapServerOptions {
  return {
    registry: registry(),
    auth: fakeAuth,
    logger,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

interface RunningServer {
  gap: GapServer;
  url: string;
  http: HttpServer;
}

interface Harness {
  base: RunningServer;
  client: Client;
  transport: StreamableHTTPClientTransport;
}

const cleanups: Array<() => Promise<void>> = [];

async function startServer(options: GapServerOptions = baseOptions()): Promise<RunningServer> {
  const gap = createGapServer(options);
  const http = createServer((req, res) => {
    void gap.handleNode(req, res);
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => {
      http.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      http.off("error", onError);
      resolve();
    };
    http.once("error", onError);
    http.once("listening", onListening);
    http.listen(0, "127.0.0.1");
  });

  const address = http.address() as AddressInfo;
  const base: RunningServer = { gap, http, url: `http://127.0.0.1:${address.port}` };

  let closed = false;
  cleanups.push(async () => {
    if (closed) return;
    closed = true;
    await gap.close().catch(() => undefined);
    await new Promise<void>((resolve) => {
      http.close(() => resolve());
      http.closeAllConnections();
    });
  });

  return base;
}

async function connect(
  base: RunningServer,
  token = "owner",
  options: { capabilities?: Record<string, unknown>; setup?: (client: Client) => void } = {},
): Promise<Harness> {
  const transport = new StreamableHTTPClientTransport(new URL(`${base.url}/mcp`), {
    requestInit: { headers: { authorization: `Bearer ${token}` } },
  });
  const client = new Client(
    { name: "gapmcp-server-test", version: "0.1.0" },
    { capabilities: (options.capabilities ?? {}) as never },
  );
  options.setup?.(client);
  await client.connect(transport);

  let closed = false;
  cleanups.push(async () => {
    if (closed) return;
    closed = true;
    await client.close().catch(() => undefined);
  });

  return { base, client, transport };
}

async function harness(
  overrides: Partial<GapServerOptions> = {},
  token = "owner",
  options: { capabilities?: Record<string, unknown>; setup?: (client: Client) => void } = {},
): Promise<Harness> {
  return connect(await startServer(baseOptions(overrides)), token, options);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface RawResult {
  content: Array<{ type: string; text?: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

async function call(
  client: Client,
  name: string,
  args: Record<string, unknown> = {},
  meta?: Record<string, unknown>,
): Promise<{
  isError: boolean;
  text: string;
  structured: Record<string, unknown>;
  raw: RawResult;
}> {
  const result = (await client.callTool({
    name,
    arguments: args,
    ...(meta ? { _meta: meta } : {}),
  })) as unknown as RawResult;
  const text = (result.content ?? [])
    .filter((item) => item.type === "text")
    .map((item) => item.text ?? "")
    .join("\n");
  return {
    isError: Boolean(result.isError),
    text,
    structured: result.structuredContent ?? {},
    raw: result,
  };
}

async function toolNames(client: Client): Promise<string[]> {
  const result = await client.listTools();
  return result.tools.map((tool) => tool.name);
}

async function waitForTask(
  client: Client,
  taskId: string,
  expected: "completed" | "cancelled",
): Promise<Record<string, unknown>> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const polled = await call(client, "gap.tasks.get", { taskId });
    if (polled.structured.status === expected) return polled.structured;
    await sleep(10);
  }
  throw new Error(`Task ${taskId} never reached ${expected}.`);
}

async function rawMcp(
  base: RunningServer,
  body: unknown,
  options: { token?: string; sessionId?: string; protocolVersion?: string; host?: string } = {},
): Promise<Response> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  if (options.sessionId) headers["mcp-session-id"] = options.sessionId;
  if (options.protocolVersion) headers["mcp-protocol-version"] = options.protocolVersion;
  return fetch(`${base.url}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

interface SseTiming {
  status: number;
  headersAt: number;
  endAt: number;
  text: string;
}

function rawSseCall(
  base: RunningServer,
  sessionId: string,
  protocolVersion: string,
  body: unknown,
): Promise<SseTiming> {
  return new Promise<SseTiming>((resolve, reject) => {
    const started = Date.now();
    const req = httpRequest(
      `${base.url}/mcp`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          authorization: "Bearer owner",
          "mcp-session-id": sessionId,
          "mcp-protocol-version": protocolVersion,
        },
      },
      (res) => {
        const headersAt = Date.now() - started;
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => {
          text += chunk;
        });
        res.on("end", () => {
          resolve({ status: res.statusCode ?? 0, headersAt, endAt: Date.now() - started, text });
        });
      },
    );
    req.on("error", reject);
    req.end(JSON.stringify(body));
  });
}

beforeEach(() => {
  resetState();
});

afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) {
    await cleanup().catch(() => undefined);
  }
});

// ---------------------------------------------------------------------------
// HTTP transport
// ---------------------------------------------------------------------------

describe("HTTP transport", () => {
  it("serves an unauthenticated health document", async () => {
    const base = await startServer();
    const response = await fetch(`${base.url}/health`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.status).toBe("ok");
    expect(body.actions).toBe(actions.length);
  });

  it("rejects an unauthenticated MCP request with an RFC 9728 challenge", async () => {
    const base = await startServer();
    const response = await rawMcp(base, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "unauthorized-test", version: "1.0.0" },
      },
    });
    expect(response.status).toBe(401);
    const challenge = response.headers.get("www-authenticate") ?? "";
    expect(challenge).toContain("Bearer");
    expect(challenge).toContain("resource_metadata");
    expect(response.headers.get("link")).toContain("oauth-protected-resource");
  });

  it("serves protected-resource metadata from the auth provider", async () => {
    const base = await startServer();
    const response = await fetch(`${base.url}/.well-known/oauth-protected-resource`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.resource).toBe("https://api.example.com/mcp");
    expect(body.authorization_servers).toEqual(["https://auth.example.com"]);
  });

  it("answers CORS preflight and returns 404 for unknown routes", async () => {
    const base = await startServer();
    const preflight = await fetch(`${base.url}/mcp`, {
      method: "OPTIONS",
      headers: {
        origin: "https://app.example.com",
        "access-control-request-method": "POST",
        "access-control-request-headers": "authorization,content-type",
      },
    });
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("access-control-allow-origin")).toBe("*");
    expect(preflight.headers.get("access-control-allow-methods")).toContain("POST");

    const missing = await fetch(`${base.url}/not-a-route`);
    expect(missing.status).toBe(404);
  });

  it("rejects a foreign Host header for DNS-rebinding protection", async () => {
    const base = await startServer();
    const response = await base.gap.fetch(new Request("http://evil.example.com/health"));
    expect(response.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// Sessions and discovery
// ---------------------------------------------------------------------------

describe("sessions and discovery", () => {
  it("lists only the tools visible to the principal", async () => {
    const owner = await harness();
    const ownerTools = await toolNames(owner.client);
    expect(ownerTools).toContain("notes.create");
    expect(ownerTools).toContain("gap.receipts.get");
    expect(ownerTools).toContain("gap.undo");
    expect(ownerTools).toContain("gap.tasks.get");

    const reader = await connect(owner.base, "reader");
    const readerTools = await toolNames(reader.client);
    expect(readerTools).toContain("notes.list");
    expect(readerTools).not.toContain("notes.create");
    expect(readerTools).not.toContain("gap.undo");
    expect(readerTools).toContain("gap.tasks.get");
  });

  it("publishes the output schema as metadata rather than MCP outputSchema", async () => {
    const owner = await harness();
    const tools = (await owner.client.listTools()).tools;
    const create = tools.find((tool) => tool.name === "notes.create");
    expect(create).toBeDefined();
    expect(create?.outputSchema).toBeUndefined();
    expect((create?._meta as Record<string, unknown>)["gap/outputSchema"]).toMatchObject({
      type: "object",
    });
  });

  it("rejects a session presented by a different principal", async () => {
    const owner = await harness();
    const sessionId = owner.transport.sessionId;
    expect(sessionId).toBeTruthy();
    const response = await rawMcp(
      owner.base,
      { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
      {
        token: "reader",
        sessionId,
        protocolVersion: owner.transport.protocolVersion ?? "2025-06-18",
      },
    );
    expect(response.status).toBe(403);
  });

  it("returns 404 for an unknown session", async () => {
    const owner = await harness();
    const response = await rawMcp(
      owner.base,
      { jsonrpc: "2.0", id: 3, method: "tools/list", params: {} },
      {
        token: "owner",
        sessionId: "sess_missing",
        protocolVersion: owner.transport.protocolVersion ?? "2025-06-18",
      },
    );
    expect(response.status).toBe(404);
  });

  it("works in stateless mode through the SDK client", async () => {
    const stateless = await harness({ sessionMode: "stateless" });
    expect(stateless.transport.sessionId).toBeUndefined();
    expect(await toolNames(stateless.client)).toContain("notes.list");
    const result = await call(stateless.client, "notes.create", { title: "Stateless" });
    expect(result.isError).toBe(false);
    expect(state.created).toBe(1);
  });

  it("streams SSE headers before a slow action finishes", async () => {
    const owner = await harness();
    const timing = await rawSseCall(
      owner.base,
      owner.transport.sessionId ?? "",
      owner.transport.protocolVersion ?? "2025-06-18",
      {
        jsonrpc: "2.0",
        id: 11,
        method: "tools/call",
        params: { name: "notes.slow", arguments: {} },
      },
    );
    expect(timing.status).toBe(200);
    expect(timing.endAt - timing.headersAt).toBeGreaterThan(150);
    expect(timing.text).toContain('"ok":true');
    expect(state.slowCalls).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Call pipeline
// ---------------------------------------------------------------------------

describe("call pipeline", () => {
  it("executes an action and returns text, structured content and a receipt", async () => {
    const received: CallRecord[] = [];
    const owner = await harness({ onCall: (record) => received.push(record) });
    const result = await call(owner.client, "notes.create", { title: "First" });
    expect(result.isError).toBe(false);
    expect(result.text).toContain("note_1");
    expect(result.structured).toMatchObject({ id: "note_1", title: "First" });

    const meta = result.raw._meta as {
      "gap/receipt": { id: string; action: string; undoable: boolean; durationMs: number };
    };
    expect(meta["gap/receipt"].id).toMatch(/^rcpt_/);
    expect(meta["gap/receipt"]).toMatchObject({
      action: "notes.create",
      undoable: true,
    });
    expect(meta["gap/receipt"].durationMs).toBeGreaterThanOrEqual(0);
    expect(received.at(-1)?.status).toBe("success");
  });

  it("returns an MCP tool error for invalid input", async () => {
    const owner = await harness();
    const result = await call(owner.client, "notes.create", { title: 4 });
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "INVALID_INPUT" } });
    expect(state.created).toBe(0);
  });

  it("returns an error for an unknown tool", async () => {
    const owner = await harness();
    const result = await call(owner.client, "notes.nope");
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "NOT_FOUND" } });
  });

  it("rejects a call the principal lacks scopes for", async () => {
    const reader = await harness({}, "reader");
    const result = await call(reader.client, "notes.create", { title: "Nope" });
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "FORBIDDEN" } });
    expect(state.created).toBe(0);
  });

  it("enforces a policy deny", async () => {
    const policy = new FakePolicy({
      "billing.refund": { decision: "deny", reason: "No refunds today.", code: "BILLING_DENIED" },
    });
    const owner = await harness({ policy });
    const result = await call(owner.client, "billing.refund", { amount: 20, reason: "test" });
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "POLICY_DENIED" } });
    expect(result.text).toContain("No refunds today.");
    expect(policy.evaluations).toContain("billing.refund");
  });

  it("runs a policy dry-run without executing the action", async () => {
    const audit = new FakeAudit();
    const policy = new FakePolicy({
      "notes.create": { decision: "allow", metadata: { dryRun: true } },
    });
    const owner = await harness({ policy, audit });
    const result = await call(owner.client, "notes.create", { title: "Dry" });
    expect(result.isError).toBe(false);
    expect(result.structured).toMatchObject({ status: "dry_run", action: "notes.create" });
    expect(state.created).toBe(0);
    expect(audit.events.at(-1)?.decision).toBe("dry_run");
  });

  it("redacts configured result paths and never audits the raw secret", async () => {
    const audit = new FakeAudit();
    const owner = await harness({ audit, redact: ["secret"] });
    const result = await call(owner.client, "notes.create", {
      title: "Redacted",
      secret: "hunter2",
    });
    expect(result.isError).toBe(false);
    expect(result.structured.secret).toBe("[REDACTED]");
    expect(JSON.stringify(result.structured)).not.toContain("hunter2");
    const event = audit.events.at(-1);
    expect(event?.decision).toBe("allowed");
    expect(JSON.stringify(event)).not.toContain("hunter2");
  });

  it("rejects a result that violates the action output schema", async () => {
    const owner = await harness();
    const result = await call(owner.client, "notes.invalidOutput");
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "INTERNAL" } });
  });

  it("enforces the action execution budget", async () => {
    const owner = await harness();
    const started = Date.now();
    const result = await call(owner.client, "notes.hang");
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "TIMEOUT" } });
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

describe("approvals", () => {
  it("parks a confirm action until a human approves, then executes on retry", async () => {
    const store = new MemoryApprovalStore();
    const owner = await harness({ approvalStore: store });
    const pending = await call(owner.client, "notes.confirm", { title: "Approved" });
    expect(pending.isError).toBe(false);
    expect(pending.structured).toMatchObject({
      status: "approval_required",
      action: "notes.confirm",
      retry: true,
    });
    const approvalId = pending.structured.approvalId as string;
    expect(store.get(approvalId)?.status).toBe("pending");

    await store.approve(approvalId, { actor: "human" });
    const retried = await call(owner.client, "notes.confirm", { title: "Approved" });
    expect(retried.isError).toBe(false);
    expect(retried.structured).toMatchObject({ id: expect.stringMatching(/^confirmed_/) });
    expect(store.get(approvalId)?.status).toBe("consumed");
    expect(state.notes.size).toBe(1);
  });

  it("rejects an approved call whose arguments changed", async () => {
    const store = new MemoryApprovalStore();
    const owner = await harness({ approvalStore: store });
    const pending = await call(owner.client, "notes.confirm", { title: "Original" });
    await store.approve(pending.structured.approvalId as string, { actor: "human" });
    const changed = await call(owner.client, "notes.confirm", { title: "Swapped" });
    expect(changed.structured).toMatchObject({ status: "approval_required" });
    expect(changed.structured.approvalId).not.toBe(pending.structured.approvalId);
    expect(state.notes.size).toBe(0);
  });

  it("reports a denied approval", async () => {
    const store = new MemoryApprovalStore();
    const owner = await harness({ approvalStore: store });
    const pending = await call(owner.client, "notes.confirm", { title: "Denied" });
    await store.deny(pending.structured.approvalId as string, {
      actor: "human",
      reason: "no",
    });
    const retried = await call(owner.client, "notes.confirm", { title: "Denied" });
    expect(retried.isError).toBe(true);
    expect(retried.structured).toMatchObject({ gapError: { code: "APPROVAL_REQUIRED" } });
    expect(retried.text).toMatch(/denied/i);
  });

  it("honours an approval token in params._meta", async () => {
    const gate = new FakeApprovalGate();
    const owner = await harness({ approvals: gate });
    const result = await call(
      owner.client,
      "notes.confirm",
      { title: "Token approved" },
      { "gap/approval": gate.token },
    );
    expect(result.isError).toBe(false);
    expect(result.structured).toMatchObject({ id: expect.stringMatching(/^confirmed_/) });

    const invalid = await call(
      owner.client,
      "notes.confirm",
      { title: "Token approved" },
      { "gap/approval": "not-a-token" },
    );
    expect(invalid.isError).toBe(true);
    expect(invalid.structured).toMatchObject({ gapError: { code: "APPROVAL_REQUIRED" } });
  });

  it("applies a policy confirm decision through the approval queue", async () => {
    const store = new MemoryApprovalStore();
    const policy = new FakePolicy({ "notes.create": { decision: "confirm" } });
    const owner = await harness({ policy, approvalStore: store });
    const pending = await call(owner.client, "notes.create", { title: "Policy gated" });
    expect(pending.structured).toMatchObject({ status: "approval_required" });
    await store.approve(pending.structured.approvalId as string, { actor: "human" });
    const retried = await call(owner.client, "notes.create", { title: "Policy gated" });
    expect(retried.isError).toBe(false);
    expect(state.created).toBe(1);
  });

  it("asks the client through MCP elicitation before the approval queue", async () => {
    const elicitations: unknown[] = [];
    const owner = await harness(
      { allowElicitation: true },
      "owner",
      {
        capabilities: { elicitation: {} },
        setup: (client) => {
          client.setRequestHandler(ElicitRequestSchema, async (request) => {
            elicitations.push(request.params);
            return { action: "accept", content: { approve: true } };
          });
        },
      },
    );
    const result = await call(owner.client, "notes.confirm", { title: "Elicited" });
    expect(result.isError).toBe(false);
    expect(result.structured).toMatchObject({ id: expect.stringMatching(/^confirmed_/) });
    expect(elicitations).toHaveLength(1);
  });

  it("reports an elicitation decline as an approval error", async () => {
    const owner = await harness(
      { allowElicitation: true },
      "owner",
      {
        capabilities: { elicitation: {} },
        setup: (client) => {
          client.setRequestHandler(ElicitRequestSchema, async () => ({
            action: "decline",
          }));
        },
      },
    );
    const result = await call(owner.client, "notes.confirm", { title: "Declined" });
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "APPROVAL_REQUIRED" } });
    expect(state.notes.size).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Rate limits and idempotency
// ---------------------------------------------------------------------------

describe("rate limits and idempotency", () => {
  it("rate limits per principal without affecting other principals", async () => {
    const owner = await harness({ rateLimit: { limit: 2, windowMs: 60_000 } });
    await call(owner.client, "notes.list");
    await call(owner.client, "notes.list");
    const limited = await call(owner.client, "notes.list");
    expect(limited.isError).toBe(true);
    expect(limited.structured).toMatchObject({ gapError: { code: "RATE_LIMITED" } });
    const gapError = limited.structured.gapError as { details?: { retryAfterMs?: number } };
    expect(gapError.details?.retryAfterMs).toBeGreaterThan(0);

    const reader = await connect(owner.base, "reader");
    const allowed = await call(reader.client, "notes.list");
    expect(allowed.isError).toBe(false);
  });

  it("replays an idempotent action once for identical arguments", async () => {
    const owner = await harness();
    const first = await call(owner.client, "notes.create", { title: "Once" });
    const second = await call(owner.client, "notes.create", { title: "Once" });
    expect(second.structured).toEqual(first.structured);
    expect(state.created).toBe(1);
    const firstMeta = first.raw._meta as { "gap/receipt": { id: string } };
    const secondMeta = second.raw._meta as { "gap/receipt": { id: string } };
    expect(secondMeta["gap/receipt"].id).toBe(firstMeta["gap/receipt"].id);
  });

  it("honours an explicit idempotency key", async () => {
    const owner = await harness();
    const first = await call(
      owner.client,
      "notes.create",
      { title: "Keyed" },
      { idempotencyKey: "key-1" },
    );
    const second = await call(
      owner.client,
      "notes.create",
      { title: "Keyed" },
      { idempotencyKey: "key-1" },
    );
    expect(second.structured).toEqual(first.structured);
    expect(state.created).toBe(1);
  });

  it("coalesces concurrent calls that share an idempotency key", async () => {
    const owner = await harness();
    const [first, second] = await Promise.all([
      call(owner.client, "notes.slowCreate", { title: "Coalesced" }),
      call(owner.client, "notes.slowCreate", { title: "Coalesced" }),
    ]);
    expect(first.isError).toBe(false);
    expect(second.isError).toBe(false);
    expect(second.structured).toEqual(first.structured);
    expect(state.created).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Receipts, undo, tasks and handoff
// ---------------------------------------------------------------------------

describe("receipts and undo", () => {
  it("reads a receipt and runs the action's inverse", async () => {
    const owner = await harness();
    const created = await call(owner.client, "notes.create", { title: "Undo me" });
    const receiptId = (
      created.raw._meta as { "gap/receipt": { id: string } }
    )["gap/receipt"].id;

    const receipt = await call(owner.client, "gap.receipts.get", { receiptId });
    expect(receipt.isError).toBe(false);
    expect(receipt.structured).toMatchObject({
      receipt: { id: receiptId, action: "notes.create", undoable: true },
      result: { id: "note_1", title: "Undo me" },
    });

    const undone = await call(owner.client, "gap.undo", { receiptId });
    expect(undone.isError).toBe(false);
    expect(undone.structured).toMatchObject({ undone: true, undoOf: receiptId });
    expect(state.undone).toBe(1);
    expect(state.notes.size).toBe(0);

    const again = await call(owner.client, "gap.undo", { receiptId });
    expect(again.isError).toBe(true);
    expect(again.structured).toMatchObject({ gapError: { code: "CONFLICT" } });
  });

  it("does not expose another principal's receipt", async () => {
    const owner = await harness();
    const created = await call(owner.client, "notes.create", { title: "Private" });
    const receiptId = (
      created.raw._meta as { "gap/receipt": { id: string } }
    )["gap/receipt"].id;

    const reader = await connect(owner.base, "reader");
    const result = await call(reader.client, "gap.receipts.get", { receiptId });
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "NOT_FOUND" } });
  });
});

describe("background tasks", () => {
  it("starts a task and returns its result through gap.tasks.get", async () => {
    const owner = await harness();
    const started = await call(owner.client, "notes.export");
    expect(started.isError).toBe(false);
    expect(started.structured).toMatchObject({ status: "working", action: "notes.export" });
    const taskId = started.structured.taskId as string;

    const task = await waitForTask(owner.client, taskId, "completed");
    expect(task.result).toEqual({ exported: 0 });
    expect(task.receipt).toMatchObject({ action: "notes.export", undoable: false });
    expect(state.tasksStarted).toBe(1);
  });

  it("cancels a running task and aborts its signal", async () => {
    const owner = await harness();
    const started = await call(owner.client, "notes.cancelable");
    const taskId = started.structured.taskId as string;

    for (let attempt = 0; attempt < 50 && state.cancelStarted === 0; attempt += 1) {
      await sleep(5);
    }
    expect(state.cancelStarted).toBe(1);
    const cancelled = await call(owner.client, "gap.tasks.cancel", { taskId });
    expect(cancelled.isError).toBe(false);
    await waitForTask(owner.client, taskId, "cancelled");
    expect(state.tasksCancelled).toBe(1);
  });
});

describe("handoff", () => {
  it("creates a signed link that can be verified and rejects tampering", async () => {
    const owner = await harness({
      handoffSecret: "test-secret",
      baseUrl: "https://app.example.com",
    });
    const result = await call(owner.client, "gap.handoff", {
      action: "notes.ui",
      args: { title: "Hello" },
    });
    expect(result.isError).toBe(false);
    const url = new URL(result.structured.url as string);
    expect(url.origin).toBe("https://app.example.com");
    expect(url.pathname).toBe("/notes/new");
    const token = url.searchParams.get("gap_state");
    expect(token).toBeTruthy();
    expect(result.structured.token).toBe(token);

    const stateToken = await verifySignedHandoffLink(token ?? "", "test-secret", {
      action: "notes.ui",
      args: { title: "Hello" },
    });
    expect(stateToken).toMatchObject({ action: "notes.ui", principalId: "usr_owner" });

    const text = token ?? "";
    const index = Math.floor(text.length / 2);
    const replacement = text[index] === "A" ? "B" : "A";
    const tampered = `${text.slice(0, index)}${replacement}${text.slice(index + 1)}`;
    expect(await verifySignedHandoffLink(tampered, "test-secret")).toBeNull();
  });

  it("rejects handoff for an action without a UI binding", async () => {
    const owner = await harness({ handoffSecret: "test-secret" });
    const result = await call(owner.client, "gap.handoff", {
      action: "notes.create",
      args: { title: "x" },
    });
    expect(result.isError).toBe(true);
    expect(result.structured).toMatchObject({ gapError: { code: "INVALID_INPUT" } });
  });

  it("only exposes gap.handoff when a handoff secret is configured", async () => {
    const withoutSecret = await harness();
    expect(await toolNames(withoutSecret.client)).not.toContain("gap.handoff");

    const withSecret = await harness({ handoffSecret: "test-secret" });
    expect(await toolNames(withSecret.client)).toContain("gap.handoff");
  });
});

// ---------------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------------

describe("observability", () => {
  it("audits allowed, denied, error and approval-required decisions without raw data", async () => {
    const audit = new FakeAudit();
    const policy = new FakePolicy({
      "billing.refund": { decision: "deny", reason: "No refunds." },
    });
    const owner = await harness({ audit, policy });

    await call(owner.client, "notes.list");
    await call(owner.client, "billing.refund", { amount: 1, reason: "x" });
    await call(owner.client, "notes.create", { title: 4 });
    await call(owner.client, "notes.confirm", { title: "Needs a human" });

    const decisions = new Set(audit.events.map((event) => event.decision));
    expect(decisions).toContain("allowed");
    expect(decisions).toContain("denied");
    expect(decisions).toContain("error");
    expect(decisions).toContain("approval_required");

    for (const event of audit.events) {
      if (event.argsHash !== undefined) expect(event.argsHash).toMatch(/^[a-f0-9]{64}$/);
      if (event.resultHash !== undefined) expect(event.resultHash).toMatch(/^[a-f0-9]{64}$/);
      expect(JSON.stringify(event)).not.toContain("Needs a human");
    }
  });

  it("keeps an inspector call log and passes a redacted result to onCall", async () => {
    const received: CallRecord[] = [];
    const owner = await harness({
      redact: ["secret"],
      onCall: (record) => received.push(record),
    });
    await call(owner.client, "notes.create", { title: "Logged", secret: "hunter2" });

    const records = owner.base.gap.calls.list();
    expect(records).toHaveLength(1);
    expect(records[0]?.action).toBe("notes.create");
    expect(records[0]?.status).toBe("success");
    expect(records[0]?.principalId).toBe("usr_owner");
    expect(JSON.stringify(records[0]?.redactedResult)).not.toContain("hunter2");
    expect(JSON.stringify(received.at(-1)?.result)).not.toContain("hunter2");
  });

  it("emits ended spans for calls and background tasks", async () => {
    const tracer = new FakeTracer();
    const owner = await harness({ tracer });
    await call(owner.client, "notes.list");
    const exportCall = await call(owner.client, "notes.export");
    await waitForTask(owner.client, exportCall.structured.taskId as string, "completed");

    const callSpan = tracer.spans.find((span) => span.name === "gap.call");
    expect(callSpan?.ended).toBe(true);
    expect(callSpan?.attributes["gap.action"]).toBe("notes.list");
    const taskSpan = tracer.spans.find((span) => span.name === "gap.task");
    expect(taskSpan?.ended).toBe(true);
  });
});
