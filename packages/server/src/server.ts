import type { IncomingMessage, ServerResponse } from "node:http";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { CallToolRequest, ElicitRequestFormParams, ElicitResult, ListToolsRequest } from "@modelcontextprotocol/sdk/types.js";
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolResult, type Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  createId,
  createLogger,
  GapError,
  hashValue,
  isAbortError,
  missingScopes,
  NOOP_SPAN,
  NOOP_TRACER,
  normalizeError,
  redact,
  searchActions,
  timeoutSignal,
  validateValue,
  VERSION,
  type ActionContext,
  type ActionRegistry,
  type AnyAction,
  type ApprovalGate,
  type ApprovalGrant,
  type AuditDecision,
  type AuditEvent,
  type AuditSink,
  type AuthProvider,
  type JsonSchema,
  type Logger,
  type PolicyDecision,
  type PolicyEngine,
  type Span,
  type ToolDescriptor,
  type Tracer,
  toToolDescriptor,
} from "gapmcp-core";
import { MemoryApprovalStore } from "./approvals.js";
import {
  anonymousAuth,
  authFromExtra,
  normalizeAuthResult,
  toAuthInfo,
  type NormalizedAuth,
  type ToolHandlerExtra,
} from "./auth.js";
import { CallStore } from "./calls.js";
import { createSignedHandoffLink } from "./handoff.js";
import {
  applyCors,
  checkRebinding,
  isInitializePayload,
  isOriginAllowed,
  jsonResponse,
  jsonRpcError,
  resolveAllowedOrigins,
  type ResolvedCors,
} from "./http-utils.js";
import { DEFAULT_IDEMPOTENCY_TTL_MS, MemoryIdempotencyStore } from "./idempotency.js";
import { handleNodeRequest } from "./node-adapter.js";
import { TokenBucketRateLimiter, unlimitedRateLimiter } from "./rate-limit.js";
import {
  errorResult,
  isCallToolResult,
  isJsonObject,
  receiptMetaFromResult,
  structuredResult,
  successResult,
  textContent,
} from "./results.js";
import { TaskManager } from "./tasks.js";
import type {
  ApprovalRecord,
  ApprovalRequiredPayload,
  ApprovalStore,
  CallReceipt,
  CallRecord,
  CallStatus,
  GapServerOptions,
  HandoffLinkPayload,
  IdempotencyStore,
  RateLimiter,
  TaskRecord,
  TaskStartedPayload,
} from "./types.js";

/** Names reserved for server-provided tools. */
const BUILTIN_NAMES: ReadonlySet<string> = new Set([
  "gap.tasks.get",
  "gap.tasks.cancel",
  "gap.receipts.get",
  "gap.search",
  "gap.undo",
  "gap.handoff",
]);

const ALLOW_ALL_POLICY: PolicyEngine = {
  evaluate: () => ({ decision: "allow" }),
};

interface ResolvedOptions {
  registry: ActionRegistry;
  name: string;
  version: string;
  instructions?: string;
  auth?: AuthProvider;
  policy: PolicyEngine;
  tracer: Tracer;
  audit?: AuditSink;
  logger: Logger;
  approvalsConfigured: boolean;
  approvals?: ApprovalGate;
  approvalStore: ApprovalStore;
  rateLimiter: RateLimiter;
  idempotency: IdempotencyStore;
  sessionMode: "stateful" | "stateless";
  baseUrl?: string;
  allowElicitation: boolean;
  handoffSecret?: string;
  enableTasks: boolean;
  callStoreLimit: number;
  onCall?: (record: CallRecord) => void;
  allowAnonymous: boolean;
  redactPaths: string[];
  timeoutMs: number;
  approvalTtlMs: number;
  handoffTtlMs: number;
  cors: ResolvedCors;
  allowedHosts?: string[];
  allowedOrigins?: string[];
  dnsProtection: boolean;
  mcpPath: string;
  metadataPath: string;
  healthPath: string;
  enableJsonResponse: boolean;
  maxRequestBodySize?: number;
  keepAliveMs?: number;
}

interface SessionEntry {
  sessionId: string;
  transport: WebStandardStreamableHTTPServerTransport;
  server: Server;
  principalId: string;
  tenantId?: string;
  scopes: string[];
  createdAt: number;
}

interface ConnectionEntry {
  transport: Transport;
  server: Server;
}

interface RunOutcome {
  response: CallToolResult;
  decision: AuditDecision;
  status: CallStatus;
  result?: unknown;
  redactedResult?: unknown;
  receipt?: CallReceipt;
  approvalId?: string;
  taskId?: string;
  metadata?: Record<string, unknown>;
}

type ApprovalResolution =
  | { kind: "approved"; grant: ApprovalGrant; mode: "token" | "store" | "elicitation" }
  | { kind: "pending"; record: ApprovalRecord };

interface BuiltinOutcome {
  response: CallToolResult;
  result?: unknown;
  redactedResult?: unknown;
  receipt?: CallReceipt;
  metadata?: Record<string, unknown>;
}

function pathMatches(path: string, configured: string): boolean {
  return path === configured || path === `${configured}/`;
}

function normalizePath(path: string): string {
  if (path.length > 1 && path.endsWith("/")) return path.slice(0, -1);
  return path;
}

function normalizeRoute(path: string): string {
  const trimmed = path.trim();
  if (!trimmed) return "/";
  return trimmed.startsWith("/") ? normalizePath(trimmed) : `/${normalizePath(trimmed)}`;
}

function isRateLimiter(value: unknown): value is RateLimiter {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { consume?: unknown }).consume === "function"
  );
}

function readMetaString(meta: Record<string, unknown>, key: string): string | undefined {
  const value = meta[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function objectSchemaForMcp(schema: JsonSchema | undefined): JsonSchema | undefined {
  if (!schema) return undefined;
  if (schema.type === "object") return schema;
  if (schema.type === undefined && isJsonObject(schema.properties)) {
    return { ...schema, type: "object" };
  }
  return undefined;
}

function toMcpTool(action: AnyAction): Tool {
  const descriptor: ToolDescriptor = toToolDescriptor(action);
  const input = objectSchemaForMcp(descriptor.inputSchema) ?? { type: "object", properties: {} };
  const output = objectSchemaForMcp(descriptor.outputSchema);
  const meta: Record<string, unknown> = { ...(descriptor._meta ?? {}) };
  // Results can be an approval-required or task-started envelope that does not
  // match the action's output schema, and errors carry `structuredContent.gapError`.
  // Advertising the action schema as the MCP tool's `outputSchema` would make
  // conforming clients reject those valid envelopes, so publish it as metadata
  // and enforce it on the server instead.
  if (output) meta["gap/outputSchema"] = output;

  const tool: Tool = {
    name: descriptor.name,
    description: descriptor.description,
    inputSchema: input as Tool["inputSchema"],
    ...(descriptor.title ? { title: descriptor.title } : {}),
    ...(descriptor.annotations ? { annotations: descriptor.annotations } : {}),
    ...(Object.keys(meta).length > 0 ? { _meta: meta } : {}),
  };
  return tool;
}

function grantFromApproval(record: ApprovalRecord): ApprovalGrant {
  return {
    id: record.id,
    action: record.action,
    argsHash: record.argsHash,
    approvedBy: record.approvedBy ?? "unknown",
    issuedAt: record.approvedAt ?? record.createdAt,
    expiresAt: record.expiresAt,
  };
}

function auditDecisionForError(code: string): AuditDecision {
  switch (code) {
    case "FORBIDDEN":
    case "POLICY_DENIED":
    case "RATE_LIMITED":
    case "APPROVAL_REQUIRED":
      return "denied";
    default:
      return "error";
  }
}

/** True when a stored record belongs to the authenticated principal and tenant. */
function isOwnedBy(
  record: { principalId: string; tenantId?: string },
  auth: NormalizedAuth,
): boolean {
  return (
    record.principalId === auth.principal.id && record.tenantId === auth.principal.tenantId
  );
}

/**
 * Execute a promise but stop waiting when `signal` aborts. The action itself
 * receives the same signal; the race ensures a non-cooperative handler cannot
 * hold a request open past its budget.
 */
function withAbort<T>(work: Promise<T>, signal: AbortSignal, message: () => string): Promise<T> {
  const aborted = () => new GapError(message(), { code: "TIMEOUT", retryable: true });
  if (signal.aborted) {
    work.catch(() => undefined);
    return Promise.reject(aborted());
  }
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (run: () => void) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      run();
    };
    const onAbort = () => {
      work.catch(() => undefined);
      finish(() => reject(aborted()));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    work.then(
      (value) => finish(() => resolve(value)),
      (error) => finish(() => reject(error)),
    );
  });
}

const SEARCH_TOOL: Tool = {
  name: "gap.search",
  title: "Search actions",
  description:
    "Search the actions visible to this principal by intent. Use it when the tool list is large and you are unsure which action to call.",
  inputSchema: {
    type: "object",
    properties: {
      query: { type: "string", description: "Natural-language description of the intent." },
      limit: {
        type: "integer",
        minimum: 1,
        maximum: 50,
        description: "Maximum results. Defaults to 10.",
      },
    },
    required: ["query"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
  _meta: { "gap/builtin": true },
};

const TASKS_GET_TOOL: Tool = {
  name: "gap.tasks.get",
  title: "Get task",
  description: "Read the status, result and receipt of a background task started by a task-backed action.",
  inputSchema: {
    type: "object",
    properties: {
      taskId: { type: "string", description: "Task id returned when the action was accepted." },
    },
    required: ["taskId"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
  _meta: { "gap/builtin": true },
};

const TASKS_CANCEL_TOOL: Tool = {
  name: "gap.tasks.cancel",
  title: "Cancel task",
  description: "Cancel a running background task. The task's abort signal is triggered immediately.",
  inputSchema: {
    type: "object",
    properties: {
      taskId: { type: "string", description: "Task id to cancel." },
    },
    required: ["taskId"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
  _meta: { "gap/builtin": true },
};

const RECEIPTS_GET_TOOL: Tool = {
  name: "gap.receipts.get",
  title: "Get receipt",
  description: "Read the receipt, arguments and redacted result of an earlier successful action call.",
  inputSchema: {
    type: "object",
    properties: {
      receiptId: { type: "string", description: "Receipt id from _meta['gap/receipt'].id." },
    },
    required: ["receiptId"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
  _meta: { "gap/builtin": true },
};

const UNDO_TOOL: Tool = {
  name: "gap.undo",
  title: "Undo action",
  description: "Run the best-effort inverse of an action using a stored receipt. Returns a new receipt.",
  inputSchema: {
    type: "object",
    properties: {
      receiptId: { type: "string", description: "Receipt id of the call to undo." },
    },
    required: ["receiptId"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false },
  _meta: { "gap/builtin": true },
};

const HANDOFF_TOOL: Tool = {
  name: "gap.handoff",
  title: "Hand off to UI",
  description: "Create a signed deep link that opens an action in the application's UI with the given arguments.",
  inputSchema: {
    type: "object",
    properties: {
      action: { type: "string", description: "Action name with a UI binding." },
      args: {
        type: "object",
        description: "Arguments for the action; must satisfy the action's input schema.",
        additionalProperties: true,
      },
    },
    required: ["action"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false },
  _meta: { "gap/builtin": true },
};

function builtinDescriptor(name: string): Tool | undefined {
  switch (name) {
    case "gap.tasks.get":
      return TASKS_GET_TOOL;
    case "gap.tasks.cancel":
      return TASKS_CANCEL_TOOL;
    case "gap.receipts.get":
      return RECEIPTS_GET_TOOL;
    case "gap.search":
      return SEARCH_TOOL;
    case "gap.undo":
      return UNDO_TOOL;
    case "gap.handoff":
      return HANDOFF_TOOL;
    default:
      return undefined;
  }
}

/**
 * Production MCP server for a Gap action registry. Owns the Streamable HTTP
 * transport, authentication, the call pipeline, approvals, idempotency,
 * background tasks, receipts and audit.
 */
export class GapServer {
  readonly registry: ActionRegistry;
  readonly calls: CallStore;
  readonly approvalStore: ApprovalStore;
  readonly tasks: TaskManager;
  readonly rateLimiter: RateLimiter;
  readonly idempotency: IdempotencyStore;

  readonly #o: ResolvedOptions;
  readonly #sessions = new Map<string, SessionEntry>();
  readonly #connections = new Set<ConnectionEntry>();
  readonly #ephemeral = new Set<{
    server: Server;
    transport: WebStandardStreamableHTTPServerTransport;
  }>();
  readonly #inFlight = new Map<string, Promise<RunOutcome>>();
  readonly #warned = new Set<string>();
  readonly #startedAt = Date.now();
  #closed = false;

  constructor(options: GapServerOptions) {
    if (!options || !options.registry) {
      throw new GapError("GapServer requires a registry.", { code: "INTERNAL", expose: false });
    }

    const sessionMode = options.sessionMode ?? "stateful";
    if (sessionMode !== "stateful" && sessionMode !== "stateless") {
      throw new GapError("sessionMode must be 'stateful' or 'stateless'.", {
        code: "INTERNAL",
        expose: false,
      });
    }

    const callStoreLimit = options.callStoreLimit ?? 500;
    if (!Number.isInteger(callStoreLimit) || callStoreLimit <= 0) {
      throw new GapError("callStoreLimit must be a positive integer.", { code: "INTERNAL", expose: false });
    }

    const timeoutMs = options.timeoutMs ?? 30_000;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new GapError("timeoutMs must be a positive number.", { code: "INTERNAL", expose: false });
    }

    const approvalTtlMs = options.approvalTtlMs ?? 5 * 60_000;
    if (!Number.isFinite(approvalTtlMs) || approvalTtlMs <= 0) {
      throw new GapError("approvalTtlMs must be a positive number.", { code: "INTERNAL", expose: false });
    }

    const handoffTtlMs = options.handoffTtlMs ?? 10 * 60_000;
    if (!Number.isFinite(handoffTtlMs) || handoffTtlMs <= 0) {
      throw new GapError("handoffTtlMs must be a positive number.", { code: "INTERNAL", expose: false });
    }

    const rateLimiter = (() => {
      if (!options.rateLimit) return unlimitedRateLimiter;
      if (isRateLimiter(options.rateLimit)) return options.rateLimit;
      return new TokenBucketRateLimiter(options.rateLimit);
    })();

    const cors: ResolvedCors =
      options.cors === false ? false : options.cors === undefined || options.cors === true ? {} : options.cors;

    const allowedOrigins = resolveAllowedOrigins({
      allowedOrigins: options.allowedOrigins,
      cors,
    });

    const baseUrl = options.baseUrl ? options.baseUrl.replace(/\/+$/g, "") : undefined;
    if (baseUrl) {
      try {
        // Validate eagerly so link construction cannot fail mid-call.
        void new URL(baseUrl);
      } catch {
        throw new GapError("baseUrl must be an absolute URL.", { code: "INTERNAL", expose: false });
      }
    }

    this.#o = {
      registry: options.registry,
      name: options.name ?? "gap",
      version: options.version ?? VERSION,
      instructions: options.instructions,
      auth: options.auth,
      policy: options.policy ?? ALLOW_ALL_POLICY,
      tracer: options.tracer ?? NOOP_TRACER,
      audit: options.audit,
      logger: options.logger ?? createLogger("warn"),
      approvalsConfigured: options.approvals !== undefined,
      approvals: options.approvals,
      approvalStore:
        options.approvalStore ?? new MemoryApprovalStore({ ttlMs: approvalTtlMs }),
      rateLimiter,
      idempotency: options.idempotency ?? new MemoryIdempotencyStore({ ttlMs: DEFAULT_IDEMPOTENCY_TTL_MS }),
      sessionMode,
      baseUrl,
      allowElicitation: options.allowElicitation ?? false,
      handoffSecret: options.handoffSecret || undefined,
      enableTasks: options.enableTasks ?? true,
      callStoreLimit,
      onCall: options.onCall,
      allowAnonymous: options.allowAnonymous ?? options.auth === undefined,
      redactPaths: [...(options.redact ?? [])],
      timeoutMs,
      approvalTtlMs,
      handoffTtlMs,
      cors,
      allowedHosts: options.allowedHosts,
      allowedOrigins,
      dnsProtection: options.enableDnsRebindingProtection ?? true,
      mcpPath: normalizeRoute(options.path ?? "/mcp"),
      metadataPath: normalizeRoute(options.protectedResourcePath ?? "/.well-known/oauth-protected-resource"),
      healthPath: normalizeRoute(options.healthPath ?? "/health"),
      enableJsonResponse: options.enableJsonResponse ?? false,
      maxRequestBodySize: options.maxRequestBodySize,
      keepAliveMs: options.keepAliveMs,
    };

    this.registry = options.registry;
    this.calls = new CallStore({ limit: callStoreLimit });
    this.approvalStore = this.#o.approvalStore;
    this.rateLimiter = rateLimiter;
    this.idempotency = this.#o.idempotency;
    this.tasks = new TaskManager({
      maxTasks: 1_000,
      closeTimeoutMs: 5_000,
    });

    for (const name of BUILTIN_NAMES) {
      if (this.registry.has(name)) {
        throw new GapError(`Tool name "${name}" is reserved by GapServer.`, {
          code: "INTERNAL",
          expose: false,
        });
      }
    }

    if (!this.#o.auth) {
      this.#warnOnce(
        "anonymous",
        this.#o.allowAnonymous
          ? "No auth provider configured; MCP requests run as the anonymous principal with ['*'] scopes. This is for development only."
          : "No auth provider configured and allowAnonymous is false; MCP requests will be rejected.",
      );
    }
  }

  /**
   * List the tools visible to a principal with the given scopes. The MCP
   * `tools/list` handler uses the authenticated principal's scopes; this
   * method is public for inspectors and tests.
   */
  listTools(scopes: readonly string[] = ["*"]): Tool[] {
    const actions = this.registry.visibleTo(scopes);
    const tools = actions.map(toMcpTool);
    const availability = this.#builtinAvailability(scopes);
    if (availability.tasks) tools.push(TASKS_GET_TOOL, TASKS_CANCEL_TOOL);
    if (availability.receipts) tools.push(RECEIPTS_GET_TOOL);
    if (availability.search) tools.push(SEARCH_TOOL);
    if (availability.undo) tools.push(UNDO_TOOL);
    if (availability.handoff) tools.push(HANDOFF_TOOL);
    return tools.sort((a, b) => a.name.localeCompare(b.name));
  }

  /** Handle a web `Request` against the MCP endpoint and auxiliary routes. */
  async fetch(request: Request): Promise<Response> {
    try {
      return await this.#guard(this.#route(request), request);
    } catch (error) {
      this.#o.logger.error(
        "Unhandled MCP HTTP error.",
        error instanceof Error ? error.message : String(error),
      );
      return this.#withCors(
        jsonResponse(500, { error: "internal_error", error_description: "Internal server error." }),
        request,
      );
    }
  }

  /** Node adapter used by `http.createServer`. Streams SSE responses. */
  async handleNode(req: IncomingMessage, res: ServerResponse): Promise<void> {
    await handleNodeRequest(this, req, res);
  }

  /**
   * Attach the server to a custom MCP transport. The transport runs as the
   * anonymous principal because there is no HTTP request to authenticate.
   * Use {@link fetch} for authenticated HTTP sessions.
   */
  async connect(transport: Transport): Promise<void> {
    if (this.#closed) throw new GapError("GapServer is closed.", { code: "UNAVAILABLE" });
    if (this.#o.auth) {
      this.#warnOnce(
        "connect-auth",
        "connect() has no HTTP request to authenticate; the transport runs as the anonymous principal.",
      );
    }
    const auth = anonymousAuth();
    const server = this.#createProtocolServer(auth);
    await server.connect(transport);
    const entry: ConnectionEntry = { transport, server };
    this.#connections.add(entry);
    const previousOnClose = transport.onclose;
    transport.onclose = () => {
      this.#connections.delete(entry);
      previousOnClose?.();
    };
  }

  /** Close every transport and abort outstanding background tasks. */
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;

    const sessions = [...this.#sessions.values()];
    this.#sessions.clear();
    await Promise.allSettled(
      sessions.map(async (entry) => {
        try {
          await entry.transport.close();
        } catch {
          // Already closed.
        }
        try {
          await entry.server.close();
        } catch {
          // Already closed.
        }
      }),
    );

    const connections = [...this.#connections];
    this.#connections.clear();
    await Promise.allSettled(
      connections.map(async (entry) => {
        try {
          await entry.transport.close();
        } catch {
          // Already closed.
        }
        try {
          await entry.server.close();
        } catch {
          // Already closed.
        }
      }),
    );

    const ephemeral = [...this.#ephemeral];
    this.#ephemeral.clear();
    await Promise.allSettled(
      ephemeral.map(async (entry) => {
        try {
          await entry.transport.close();
        } catch {
          // Already closed.
        }
        try {
          await entry.server.close();
        } catch {
          // Already closed.
        }
      }),
    );

    await this.tasks.close();
  }

  // ---------------------------------------------------------------------------
  // HTTP routing
  // ---------------------------------------------------------------------------

  async #route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = normalizePath(url.pathname);

    const rebinding = checkRebinding(request, {
      enabled: this.#o.dnsProtection,
      allowedHosts: this.#o.allowedHosts,
      allowedOrigins: this.#o.allowedOrigins,
      baseUrl: this.#o.baseUrl,
    });
    if (rebinding) return rebinding;

    if (request.method === "OPTIONS") {
      const headers = new Headers();
      applyCors(headers, request, this.#o.cors);
      return new Response(null, { status: 204, headers });
    }

    if (pathMatches(path, this.#o.healthPath)) {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return this.#methodNotAllowed("GET, HEAD");
      }
      return jsonResponse(200, {
        status: "ok",
        name: this.#o.name,
        version: this.#o.version,
        uptimeMs: Date.now() - this.#startedAt,
        sessions: this.#o.sessionMode === "stateful" ? this.#sessions.size : 0,
        actions: this.registry.size,
      });
    }

    if (path === this.#o.metadataPath || path.startsWith(`${this.#o.metadataPath}/`)) {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return this.#methodNotAllowed("GET, HEAD");
      }
      return jsonResponse(200, this.#metadataDocument(request), {
        "cache-control": "no-store",
      });
    }

    if (!pathMatches(path, this.#o.mcpPath)) {
      return jsonResponse(404, { error: "not_found", error_description: "Route not found." });
    }

    if (request.method !== "POST" && request.method !== "GET" && request.method !== "DELETE") {
      return this.#methodNotAllowed("POST, GET, DELETE");
    }

    if (!isOriginAllowed(request, this.#o.cors)) {
      return jsonResponse(403, {
        error: "forbidden",
        error_description: "The Origin header is not allowed by this server.",
      });
    }

    let auth: NormalizedAuth | null;
    try {
      auth = await this.#authenticate(request);
    } catch (error) {
      this.#o.logger.error(
        "Authentication provider failed.",
        error instanceof Error ? error.message : String(error),
      );
      auth = null;
    }
    if (!auth) return this.#unauthorized(request);

    return this.#o.sessionMode === "stateless"
      ? this.#handleStateless(request, auth)
      : this.#handleStateful(request, auth);
  }

  #methodNotAllowed(allow: string): Response {
    const response = jsonRpcError(405, -32600, "Method not allowed.");
    response.headers.set("allow", allow);
    return response;
  }

  #withCors(response: Response, request: Request): Response {
    const headers = new Headers(response.headers);
    applyCors(headers, request, this.#o.cors);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }

  #guard(responsePromise: Promise<Response>, request: Request): Promise<Response> {
    return responsePromise.then(
      (response) => this.#withCors(response, request),
      (error: unknown) => {
        this.#o.logger.error(
          "Unhandled MCP route error.",
          error instanceof Error ? error.message : String(error),
        );
        return this.#withCors(
          jsonResponse(500, { error: "internal_error", error_description: "Internal server error." }),
          request,
        );
      },
    );
  }

  // ---------------------------------------------------------------------------
  // Authentication / metadata
  // ---------------------------------------------------------------------------

  async #authenticate(request: Request): Promise<NormalizedAuth | null> {
    if (!this.#o.auth) return this.#o.allowAnonymous ? anonymousAuth() : null;
    let result;
    try {
      result = await this.#o.auth.authenticate(request);
    } catch (error) {
      // A broken auth provider must fail closed even when anonymous access is
      // otherwise allowed.
      this.#o.logger.warn(
        "Authentication provider threw; rejecting the request.",
        error instanceof Error ? error.message : String(error),
      );
      return null;
    }
    if (!result) {
      if (!this.#o.allowAnonymous) return null;
      this.#warnOnce(
        "auth-fallback",
        "Authentication failed; falling back to the anonymous principal because allowAnonymous is true.",
      );
      return anonymousAuth();
    }
    const normalized = normalizeAuthResult(result);
    if (!normalized) {
      this.#o.logger.warn("Authentication returned an invalid principal; rejecting the request.");
      return null;
    }
    return normalized;
  }

  #metadataDocument(request: Request): Record<string, unknown> {
    if (this.#o.auth?.protectedResourceMetadata) {
      try {
        return this.#o.auth.protectedResourceMetadata();
      } catch (error) {
        this.#o.logger.warn(
          "protectedResourceMetadata() failed; serving a minimal document.",
          error instanceof Error ? error.message : String(error),
        );
      }
    }
    const scopes = new Set<string>();
    for (const action of this.registry.list()) {
      for (const scope of action.scopes ?? []) {
        if (scope !== "*") scopes.add(scope);
      }
    }
    return {
      resource: this.#baseUrlFor(request),
      authorization_servers: [],
      scopes_supported: [...scopes].sort(),
      bearer_methods_supported: ["header"],
    };
  }

  #baseUrlFor(request: Request): string {
    if (this.#o.baseUrl) return this.#o.baseUrl;
    try {
      return new URL("/", request.url).origin;
    } catch {
      return request.url;
    }
  }

  #metadataUrl(request: Request): string {
    return `${this.#baseUrlFor(request)}${this.#o.metadataPath}`;
  }

  #unauthorized(request: Request): Response {
    const metadataUrl = this.#metadataUrl(request);
    let challenge: string | undefined;
    if (this.#o.auth?.challenge) {
      try {
        challenge = this.#o.auth.challenge();
      } catch (error) {
        this.#o.logger.warn(
          "challenge() failed; using the default bearer challenge.",
          error instanceof Error ? error.message : String(error),
        );
      }
    }
    const document = this.#metadataDocument(request);
    const challengeValue =
      challenge && challenge.trim().length > 0 ? challenge.trim() : `Bearer realm="gap"`;
    const authenticate = /resource_metadata=/i.test(challengeValue)
      ? challengeValue
      : `${challengeValue}, resource_metadata="${metadataUrl}"`;
    return jsonResponse(
      401,
      {
        error: "unauthorized",
        error_description: "Authentication required.",
        resource_metadata: metadataUrl,
        protected_resource_metadata: document,
      },
      {
        "www-authenticate": authenticate,
        link: `<${metadataUrl}>; rel="http://www.rfc-editor.org/rfc/rfc9728#metadata"`,
      },
    );
  }

  // ---------------------------------------------------------------------------
  // Streamable HTTP sessions
  // ---------------------------------------------------------------------------

  async #handleStateful(request: Request, auth: NormalizedAuth): Promise<Response> {
    const sessionId = request.headers.get("mcp-session-id");
    if (sessionId) {
      const entry = this.#sessions.get(sessionId);
      if (!entry) {
        return jsonRpcError(404, -32001, "Session not found.");
      }
      if (
        entry.principalId !== auth.principal.id ||
        entry.tenantId !== auth.principal.tenantId
      ) {
        return jsonRpcError(403, -32002, "This session belongs to a different principal.");
      }
      return entry.transport.handleRequest(request, { authInfo: toAuthInfo(auth) });
    }

    if (request.method !== "POST") {
      return jsonRpcError(400, -32600, "Bad Request: Mcp-Session-Id header is required.");
    }

    let payload: unknown;
    try {
      payload = await request.clone().json();
    } catch {
      return jsonRpcError(400, -32700, "Parse error: Invalid JSON.");
    }
    if (!isInitializePayload(payload)) {
      return jsonRpcError(400, -32600, "Bad Request: Mcp-Session-Id header is required.");
    }

    const server = this.#createProtocolServer(auth);
    let session: SessionEntry | undefined;
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: () => createId("sess"),
      onsessioninitialized: (id) => {
        session = {
          sessionId: id,
          transport,
          server,
          principalId: auth.principal.id,
          tenantId: auth.principal.tenantId,
          scopes: [...auth.scopes],
          createdAt: Date.now(),
        };
        this.#sessions.set(id, session);
      },
      onsessionclosed: (id) => {
        this.#sessions.delete(id);
      },
      enableJsonResponse: this.#o.enableJsonResponse,
      ...(this.#o.maxRequestBodySize === undefined ? {} : { maxRequestBodySize: this.#o.maxRequestBodySize }),
      ...(this.#o.keepAliveMs === undefined ? {} : { keepAliveMs: this.#o.keepAliveMs }),
    });
    transport.onclose = () => {
      if (transport.sessionId) this.#sessions.delete(transport.sessionId);
    };
    transport.onerror = (error) => {
      this.#o.logger.warn("MCP transport error.", error.message);
    };

    try {
      await server.connect(transport);
      const response = await transport.handleRequest(request, { authInfo: toAuthInfo(auth) });
      if (!session) {
        // Initialization failed; do not leak the transport.
        await transport.close().catch(() => undefined);
        await server.close().catch(() => undefined);
      }
      return response;
    } catch (error) {
      if (transport.sessionId) this.#sessions.delete(transport.sessionId);
      await transport.close().catch(() => undefined);
      await server.close().catch(() => undefined);
      throw error;
    }
  }

  async #handleStateless(request: Request, auth: NormalizedAuth): Promise<Response> {
    if (request.method !== "POST") {
      const response = jsonRpcError(405, -32600, "Method not allowed in stateless mode.");
      response.headers.set("allow", "POST");
      return response;
    }

    const server = this.#createProtocolServer(auth);
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: this.#o.enableJsonResponse,
      ...(this.#o.maxRequestBodySize === undefined ? {} : { maxRequestBodySize: this.#o.maxRequestBodySize }),
      ...(this.#o.keepAliveMs === undefined ? {} : { keepAliveMs: this.#o.keepAliveMs }),
    });
    transport.onerror = (error) => {
      this.#o.logger.warn("MCP transport error.", error.message);
    };

    try {
      await server.connect(transport);
      const entry = { server, transport };
      this.#ephemeral.add(entry);
      let response: Response;
      try {
        response = await transport.handleRequest(request, { authInfo: toAuthInfo(auth) });
      } catch (error) {
        this.#ephemeral.delete(entry);
        throw error;
      }
      return this.#closeWhenConsumed(response, server, transport, () => {
        this.#ephemeral.delete(entry);
      });
    } catch (error) {
      await transport.close().catch(() => undefined);
      await server.close().catch(() => undefined);
      throw error;
    }
  }

  #closeWhenConsumed(
    response: Response,
    server: Server,
    transport: WebStandardStreamableHTTPServerTransport,
    onClose?: () => void,
  ): Response {
    let closed = false;
    const cleanup = async () => {
      if (closed) return;
      closed = true;
      onClose?.();
      try {
        await transport.close();
      } catch {
        // Already closed.
      }
      try {
        await server.close();
      } catch {
        // Already closed.
      }
    };

    if (!response.body) {
      void cleanup();
      return response;
    }

    const reader = response.body.getReader();
    const stream = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const { done, value } = await reader.read();
          if (done) {
            controller.close();
            void cleanup();
          } else {
            controller.enqueue(value);
          }
        } catch (error) {
          controller.error(error);
          void cleanup();
        }
      },
      async cancel(reason) {
        try {
          await reader.cancel(reason);
        } catch {
          // Already cancelled.
        } finally {
          await cleanup();
        }
      },
    });
    return new Response(stream, {
      status: response.status,
      statusText: response.statusText,
      headers: new Headers(response.headers),
    });
  }

  // ---------------------------------------------------------------------------
  // MCP protocol wiring
  // ---------------------------------------------------------------------------

  #createProtocolServer(fallbackAuth: NormalizedAuth): Server {
    const server = new Server(
      { name: this.#o.name, version: this.#o.version },
      {
        capabilities: { tools: { listChanged: false } },
        ...(this.#o.instructions === undefined ? {} : { instructions: this.#o.instructions }),
      },
    );

    server.setRequestHandler(ListToolsRequestSchema, async (_request: ListToolsRequest, extra) => {
      const auth = authFromExtra(extra, fallbackAuth);
      return { tools: this.listTools(auth.scopes) };
    });

    server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest, extra) => {
      const auth = authFromExtra(extra, fallbackAuth);
      try {
        return await this.#handleToolCall(
          request.params.name,
          request.params.arguments ?? {},
          (request.params._meta ?? {}) as Record<string, unknown>,
          auth,
          extra,
          server,
        );
      } catch (error) {
        // Every expected failure is already converted by the pipeline. This is
        // a last-resort guard so a bug never turns into a JSON-RPC 500.
        return errorResult(normalizeError(error));
      }
    });

    return server;
  }

  async #handleToolCall(
    name: string,
    args: Record<string, unknown>,
    meta: Record<string, unknown>,
    auth: NormalizedAuth,
    extra: ToolHandlerExtra,
    server: Server,
  ): Promise<CallToolResult> {
    if (BUILTIN_NAMES.has(name)) {
      return this.#handleBuiltin(name, args, auth, extra);
    }
    return this.#handleActionCall(name, args, meta, auth, extra, server);
  }

  // ---------------------------------------------------------------------------
  // Action pipeline
  // ---------------------------------------------------------------------------

  async #handleActionCall(
    name: string,
    args: Record<string, unknown>,
    meta: Record<string, unknown>,
    auth: NormalizedAuth,
    extra: ToolHandlerExtra,
    server: Server,
  ): Promise<CallToolResult> {
    const started = Date.now();
    const traceId = createId("trace");
    const callId = createId("rcpt");
    const logger = this.#o.logger.child?.({ tool: name, traceId }) ?? this.#o.logger;
    const span = this.#span("gap.call", {
      "gap.action": name,
      "gap.trace_id": traceId,
      "gap.principal_id": auth.principal.id,
    });

    let argsHash: string | undefined;
    let resultHash: string | undefined;
    let auditDecision: AuditDecision = "error";
    let auditError: GapError | undefined;
    let auditApprovalId: string | undefined;
    let auditMetadata: Record<string, unknown> | undefined;
    let callArgs: unknown = args;
    let approvalId: string | undefined;

    try {
      const action = this.registry.get(name);
      if (!action) {
        throw new GapError(`Unknown tool "${name}".`, { code: "NOT_FOUND" });
      }
      argsHash = await hashValue(args);

      const missing = missingScopes(auth.scopes, action.scopes);
      if (missing.length > 0) {
        throw new GapError(`Missing required scope(s): ${missing.join(", ")}.`, {
          code: "FORBIDDEN",
          details: { missingScopes: missing },
        });
      }

      const ctx = this.#createContext(auth, extra, traceId, span, logger);
      const decision = await this.#evaluatePolicy(action, args, ctx);
      if (decision.decision === "deny") {
        throw new GapError(decision.reason ?? "Blocked by policy.", {
          code: "POLICY_DENIED",
          details: {
            ...(decision.code ? { policyCode: decision.code } : {}),
            ...(decision.limits ? { limits: decision.limits } : {}),
          },
        });
      }
      if (decision.metadata?.dryRun === true) ctx.dryRun = true;
      const redactPaths = [...new Set([...(decision.redactPaths ?? []), ...this.#o.redactPaths])];

      const limit = await this.#o.rateLimiter.consume(`${auth.principal.id}:${name}`, 1);
      if (!limit.allowed) {
        throw new GapError(
          `Rate limit exceeded. Retry in ${limit.retryAfterMs}ms.`,
          {
            code: "RATE_LIMITED",
            details: {
              retryAfterMs: limit.retryAfterMs,
              limit: limit.limit,
              remaining: limit.remaining,
              resetAt: limit.resetAt,
            },
            retryable: true,
          },
        );
      }

      const validation = validateValue(action.input, args);
      if (!validation.success) {
        throw new GapError(`Invalid input for "${name}".`, {
          code: "INVALID_INPUT",
          details: { issues: validation.issues },
        });
      }
      const input = validation.data;
      callArgs = input;

      const explicitKey = readMetaString(meta, "idempotencyKey");
      const autoKey =
        explicitKey === undefined && action.idempotent === true
          ? `auto:${await hashValue({ principalId: auth.principal.id, action: name, args: input })}`
          : undefined;
      const idempotencyKey =
        explicitKey === undefined ? autoKey : `${auth.principal.id}:${explicitKey}`;
      if (idempotencyKey) ctx.idempotencyKey = explicitKey ?? autoKey;

      if (idempotencyKey) {
        const cached = await this.idempotency.get(idempotencyKey);
        if (cached && isCallToolResult(cached.value)) {
          const replay = this.#replayOutcome(cached.value);
          auditDecision = replay.decision;
          auditMetadata = { idempotentReplay: true, ...(replay.metadata ?? {}) };
          this.#recordCall(
            this.#callRecord({
              id: callId,
              action: name,
              auth,
              status: replay.status,
              args: callArgs,
              result: replay.result,
              redactedResult: replay.redactedResult,
              durationMs: Date.now() - started,
              receipt: replay.receipt,
              approvalId: replay.approvalId,
              traceId,
              replayed: true,
              metadata: { idempotentReplay: true },
            }),
          );
          return replay.response;
        }

        const inFlight = this.#inFlight.get(idempotencyKey);
        if (inFlight) {
          const shared = await inFlight;
          const replay = this.#replayOutcome(shared.response);
          auditDecision = replay.decision;
          auditMetadata = { idempotentReplay: true, coalesced: true, ...(replay.metadata ?? {}) };
          this.#recordCall(
            this.#callRecord({
              id: callId,
              action: name,
              auth,
              status: replay.status,
              args: callArgs,
              result: replay.result,
              redactedResult: replay.redactedResult,
              durationMs: Date.now() - started,
              receipt: replay.receipt,
              approvalId: replay.approvalId,
              traceId,
              replayed: true,
              metadata: { idempotentReplay: true, coalesced: true },
            }),
          );
          return replay.response;
        }

        // Re-check the store after the asynchronous in-flight lookup. This
        // closes the window where the first caller committed its result and
        // removed the in-flight entry between our two reads.
        const committed = await this.idempotency.get(idempotencyKey);
        if (committed && isCallToolResult(committed.value)) {
          const replay = this.#replayOutcome(committed.value);
          auditDecision = replay.decision;
          auditMetadata = { idempotentReplay: true, ...(replay.metadata ?? {}) };
          this.#recordCall(
            this.#callRecord({
              id: callId,
              action: name,
              auth,
              status: replay.status,
              args: callArgs,
              result: replay.result,
              redactedResult: replay.redactedResult,
              durationMs: Date.now() - started,
              receipt: replay.receipt,
              approvalId: replay.approvalId,
              traceId,
              replayed: true,
              metadata: { idempotentReplay: true },
            }),
          );
          return replay.response;
        }

        const run = this.#runAction({
          action,
          name,
          rawArgs: args,
          input,
          meta,
          argsHash,
          ctx,
          auth,
          extra,
          server,
          callId,
          redactPaths,
          policyConfirm: decision.decision === "confirm",
          logger,
          traceId,
        });
        this.#inFlight.set(idempotencyKey, run);
        try {
          const outcome = await run;
          auditDecision = outcome.decision;
          auditApprovalId = outcome.approvalId;
          auditMetadata = outcome.metadata;
          resultHash = outcome.receipt?.resultHash;
          approvalId = outcome.approvalId;
          this.#recordCall(
            this.#callRecord({
              id: callId,
              action: name,
              auth,
              status: outcome.status,
              args: callArgs,
              result: outcome.result,
              redactedResult: outcome.redactedResult,
              durationMs: Date.now() - started,
              receipt: outcome.receipt,
              approval: ctx.approval,
              approvalId: outcome.approvalId,
              traceId,
              taskId: outcome.taskId,
              metadata: outcome.metadata,
            }),
          );
          if (
            !outcome.response.isError &&
            outcome.decision !== "dry_run" &&
            outcome.decision !== "approval_required"
          ) {
            try {
              await this.idempotency.set(idempotencyKey, {
                key: idempotencyKey,
                value: outcome.response,
                createdAt: Date.now(),
                expiresAt: Date.now() + DEFAULT_IDEMPOTENCY_TTL_MS,
              });
            } catch (error) {
              logger.warn(
                "Failed to persist an idempotent result.",
                error instanceof Error ? error.message : String(error),
              );
            }
          }
          return outcome.response;
        } finally {
          if (this.#inFlight.get(idempotencyKey) === run) this.#inFlight.delete(idempotencyKey);
        }
      }

      const outcome = await this.#runAction({
        action,
        name,
        rawArgs: args,
        input,
        meta,
        argsHash,
        ctx,
        auth,
        extra,
        server,
        callId,
        redactPaths,
        policyConfirm: decision.decision === "confirm",
        logger,
        traceId,
      });
      auditDecision = outcome.decision;
      auditApprovalId = outcome.approvalId;
      auditMetadata = outcome.metadata;
      resultHash = outcome.receipt?.resultHash;
      approvalId = outcome.approvalId;
      this.#recordCall(
        this.#callRecord({
          id: callId,
          action: name,
          auth,
          status: outcome.status,
          args: callArgs,
          result: outcome.result,
          redactedResult: outcome.redactedResult,
          durationMs: Date.now() - started,
          receipt: outcome.receipt,
          approval: ctx.approval,
          approvalId: outcome.approvalId,
          traceId,
          taskId: outcome.taskId,
          metadata: outcome.metadata,
        }),
      );
      return outcome.response;
    } catch (error) {
      const gap = normalizeError(error);
      const message = gap.expose ? gap.message : "Internal error.";
      if (!gap.expose) logger.error("Tool call failed.", gap.message);
      else logger.debug?.("Tool call rejected.", message);
      this.#safeRecordException(span, error);
      auditError = gap;
      auditDecision = auditDecisionForError(gap.code);
      this.#recordCall(
        this.#callRecord({
          id: callId,
          action: name,
          auth,
          status: "error",
          args: callArgs,
          error: {
            code: gap.code,
            message,
            details: gap.expose ? gap.details : undefined,
          },
          durationMs: Date.now() - started,
          approvalId,
          traceId,
        }),
      );
      return errorResult(gap, traceId);
    } finally {
      await this.#emitAudit({
        action: name,
        auth,
        decision: auditDecision,
        argsHash,
        resultHash,
        durationMs: Date.now() - started,
        error: auditError,
        approvalId: auditApprovalId,
        traceId,
        metadata: auditMetadata,
      });
      this.#safeEndSpan(span);
    }
  }

  async #runAction(options: {
    action: AnyAction;
    name: string;
    rawArgs: Record<string, unknown>;
    input: unknown;
    meta: Record<string, unknown>;
    argsHash: string;
    ctx: ActionContext;
    auth: NormalizedAuth;
    extra: ToolHandlerExtra;
    server: Server;
    callId: string;
    redactPaths: string[];
    policyConfirm: boolean;
    logger: Logger;
    traceId: string;
  }): Promise<RunOutcome> {
    const { action, name, input, argsHash, ctx, auth, extra, server, callId, redactPaths } = options;

    if (ctx.dryRun) {
      const payload = {
        status: "dry_run",
        action: name,
        args: redact(input, redactPaths),
      };
      return {
        response: successResult({ value: payload, traceId: options.traceId }),
        decision: "dry_run",
        status: "dry_run",
        result: payload,
        redactedResult: payload,
        metadata: { dryRun: true },
      };
    }

    const needsConfirm =
      options.policyConfirm || (await this.#actionNeedsConfirm(action, input, ctx));
    let approval: ApprovalResolution = { kind: "approved", grant: syntheticGrant(action, name, argsHash), mode: "store" };
    let hasApproval = false;

    if (needsConfirm) {
      approval = await this.#resolveApproval({
        action,
        name,
        rawArgs: options.rawArgs,
        meta: options.meta,
        argsHash,
        ctx,
        auth,
        extra,
        server,
      });
      if (approval.kind === "pending") {
        const record = approval.record;
        const payload: ApprovalRequiredPayload = {
          status: "approval_required",
          action: name,
          approvalId: record.id,
          approveUrl: this.#approvalUrl(record.id, extra),
          retry: true,
          argsHash,
          expiresAt: new Date(record.expiresAt).toISOString(),
        };
        return {
          response: structuredResult(
            { ...payload },
            `Approval required for ${name}.\nApproval ID: ${record.id}\nApprove at: ${payload.approveUrl}\nRetry the same call after approval.`,
            options.traceId,
          ),
          decision: "approval_required",
          status: "approval_required",
          approvalId: record.id,
          metadata: { approvalId: record.id },
        };
      }
      ctx.approval = approval.grant;
      hasApproval = true;
    }

    const approvalId = hasApproval ? approval.grant.id : undefined;
    const approvalMode = hasApproval && approval.kind === "approved" ? approval.mode : undefined;

    if (action.task === true && this.#o.enableTasks) {
      const taskId = createId("task");
      const task = this.tasks.start({
        id: taskId,
        action: name,
        principalId: auth.principal.id,
        tenantId: auth.principal.tenantId,
        traceId: options.traceId,
        approvalId,
        input,
        callId,
        run: (signal) =>
          this.#runTask({
            action,
            name,
            input,
            argsHash,
            ctx,
            auth,
            callId,
            taskId,
            signal,
            redactPaths,
            approvalId,
            traceId: options.traceId,
          }),
      });
      const payload: TaskStartedPayload = { status: "working", taskId: task.id, action: name };
      return {
        response: structuredResult(
          { ...payload },
          `Task started: ${task.id}. Poll gap.tasks.get to read the result.`,
          options.traceId,
        ),
        decision: "allowed",
        status: "task",
        taskId: task.id,
        approvalId,
        metadata: {
          taskId: task.id,
          ...(approvalMode ? { approvalMode } : {}),
        },
      };
    }

    const signal = timeoutSignal(action.timeoutMs ?? this.#o.timeoutMs, extra.signal);
    ctx.signal = signal;
    const started = Date.now();
    const work = Promise.resolve().then(() => action.execute(input, ctx));
    const raw = await withAbort(work, signal, () =>
      extra.signal.aborted ? "The action was cancelled." : "The action timed out.",
    );
    if (signal.aborted) {
      throw new GapError("The action timed out or was cancelled.", { code: "TIMEOUT", retryable: true });
    }

    const output = this.#validateOutput(action, raw);
    const redacted = redact(output, redactPaths);
    const durationMs = Date.now() - started;
    const receipt = await this.#createReceipt({
      id: callId,
      action: action.name,
      auth,
      argsHash,
      result: output,
      durationMs,
      approvalId,
      traceId: options.traceId,
    });

    return {
      response: successResult({ value: redacted, receipt, traceId: options.traceId }),
      decision: "allowed",
      status: "success",
      result: output,
      redactedResult: redacted,
      receipt,
      approvalId,
      metadata: approvalMode ? { approvalMode } : undefined,
    };
  }

  async #runTask(input: {
    action: AnyAction;
    name: string;
    input: unknown;
    argsHash: string;
    ctx: ActionContext;
    auth: NormalizedAuth;
    callId: string;
    taskId: string;
    signal: AbortSignal;
    redactPaths: string[];
    approvalId?: string;
    traceId: string;
  }): Promise<{ result: unknown; receipt?: CallReceipt }> {
    const started = Date.now();
    const span = this.#span("gap.task", {
      "gap.action": input.name,
      "gap.trace_id": input.traceId,
      "gap.task_id": input.taskId,
    });
    const signal = timeoutSignal(input.action.timeoutMs ?? this.#o.timeoutMs, input.signal);
    const ctx: ActionContext = { ...input.ctx, signal, span, idempotencyKey: undefined };

    try {
      const work = Promise.resolve().then(() => input.action.execute(input.input, ctx));
      const raw = await withAbort(work, signal, () =>
        input.signal.aborted ? "The task was cancelled." : "The task timed out.",
      );
      const output = this.#validateOutput(input.action, raw);
      const redacted = redact(output, input.redactPaths);
      const durationMs = Date.now() - started;
      const receipt = await this.#createReceipt({
        id: input.callId,
        action: input.action.name,
        auth: input.auth,
        argsHash: input.argsHash,
        result: output,
        durationMs,
        approvalId: input.approvalId,
        traceId: input.traceId,
      });
      this.#recordCall(
        this.#callRecord({
          id: input.callId,
          action: input.name,
          auth: input.auth,
          status: "success",
          args: input.input,
          result: output,
          redactedResult: redacted,
          durationMs: Date.now() - started,
          receipt,
          approval: input.ctx.approval,
          approvalId: input.approvalId,
          traceId: input.traceId,
          taskId: input.taskId,
          metadata: { taskId: input.taskId },
        }),
      );
      await this.#emitAudit({
        action: input.name,
        auth: input.auth,
        decision: "allowed",
        argsHash: input.argsHash,
        resultHash: receipt.resultHash,
        durationMs: Date.now() - started,
        approvalId: input.approvalId,
        traceId: input.traceId,
        metadata: { taskId: input.taskId, background: true },
      });
      return { result: redacted, receipt };
    } catch (error) {
      const gap = normalizeError(error);
      const message = gap.expose ? gap.message : "Internal error.";
      this.#safeRecordException(span, error);
      this.#recordCall(
        this.#callRecord({
          id: input.callId,
          action: input.name,
          auth: input.auth,
          status: "error",
          args: input.input,
          error: { code: gap.code, message, details: gap.expose ? gap.details : undefined },
          durationMs: Date.now() - started,
          approvalId: input.approvalId,
          traceId: input.traceId,
          taskId: input.taskId,
          metadata: { taskId: input.taskId, cancelled: input.signal.aborted },
        }),
      );
      await this.#emitAudit({
        action: input.name,
        auth: input.auth,
        decision: input.signal.aborted ? "denied" : "error",
        argsHash: input.argsHash,
        durationMs: Date.now() - started,
        error: gap,
        approvalId: input.approvalId,
        traceId: input.traceId,
        metadata: { taskId: input.taskId, background: true, cancelled: input.signal.aborted },
      });
      throw gap;
    } finally {
      this.#safeEndSpan(span);
    }
  }

  // ---------------------------------------------------------------------------
  // Approvals
  // ---------------------------------------------------------------------------

  async #actionNeedsConfirm(action: AnyAction, input: unknown, ctx: ActionContext): Promise<boolean> {
    if (action.confirm === undefined) return false;
    if (typeof action.confirm === "boolean") return action.confirm;
    return Boolean(await action.confirm(input, ctx));
  }

  async #resolveApproval(input: {
    action: AnyAction;
    name: string;
    rawArgs: Record<string, unknown>;
    meta: Record<string, unknown>;
    argsHash: string;
    ctx: ActionContext;
    auth: NormalizedAuth;
    extra: ToolHandlerExtra;
    server: Server;
  }): Promise<ApprovalResolution> {
    const { name, rawArgs, meta, argsHash, auth, extra } = input;
    const principalId = auth.principal.id;
    const token = readMetaString(meta, "gap/approval");

    if (token && this.#o.approvalsConfigured) {
      const gate = this.#o.approvals;
      if (gate) {
        const grant = await gate.verify(token, { action: name, args: rawArgs, principalId });
        if (
          !grant ||
          grant.action !== name ||
          grant.argsHash !== argsHash ||
          grant.expiresAt <= Date.now()
        ) {
          throw new GapError("Invalid or expired approval token.", {
            code: "APPROVAL_REQUIRED",
            details: { reason: "invalid_token" },
          });
        }
        return { kind: "approved", grant, mode: "token" };
      }
    }

    const now = Date.now();
    const records = await this.#o.approvalStore.list({
      principalId,
      tenantId: auth.principal.tenantId,
      action: name,
      argsHash,
    });

    const approved = records.find(
      (record) => record.status === "approved" && record.expiresAt > now,
    );
    if (approved) {
      try {
        const consumed = await this.#o.approvalStore.consume(approved.id);
        return { kind: "approved", grant: grantFromApproval(consumed), mode: "store" };
      } catch (error) {
        const gap = normalizeError(error);
        if (gap.code === "CONFLICT") {
          throw new GapError("This approval has already been used.", {
            code: "APPROVAL_REQUIRED",
            details: { approvalId: approved.id, status: "consumed" },
          });
        }
        throw gap;
      }
    }

    const pending = records.find((record) => record.status === "pending" && record.expiresAt > now);
    if (pending) return { kind: "pending", record: pending };

    const denied = records.find((record) => record.status === "denied");
    if (denied) {
      throw new GapError("Approval was denied.", {
        code: "APPROVAL_REQUIRED",
        details: { approvalId: denied.id, status: "denied", reason: denied.reason },
      });
    }

    const created = await this.#o.approvalStore.create({
      principalId,
      tenantId: auth.principal.tenantId,
      action: name,
      argsHash,
      args: rawArgs,
      ttlMs: this.#o.approvalTtlMs,
      metadata: { traceId: input.ctx.traceId },
    });

    if (this.#o.allowElicitation && input.server.getClientCapabilities()?.elicitation) {
      return this.#elicitApproval({
        record: created,
        name,
        extra,
        server: input.server,
        principalId,
      });
    }

    return { kind: "pending", record: created };
  }

  async #elicitApproval(input: {
    record: ApprovalRecord;
    name: string;
    extra: ToolHandlerExtra;
    server: Server;
    principalId: string;
  }): Promise<ApprovalResolution> {
    const params: ElicitRequestFormParams = {
      mode: "form",
      message: `Approve running "${input.name}" with the arguments you provided?`,
      requestedSchema: {
        type: "object",
        properties: {
          approve: {
            type: "boolean",
            title: "Approve",
            description: "Run this action once with the parameters from the tool call.",
            default: false,
          },
        },
        required: ["approve"],
      },
    };

    let result: ElicitResult;
    try {
      result = await input.server.elicitInput(params, { relatedRequestId: input.extra.requestId });
    } catch (error) {
      // The client advertised elicitation but the request failed. Fall back to
      // the durable approval queue rather than failing the call.
      this.#o.logger.warn(
        "MCP elicitation failed; falling back to the approval queue.",
        error instanceof Error ? error.message : String(error),
      );
      return { kind: "pending", record: input.record };
    }

    if (result.action === "accept" && result.content?.approve === true) {
      const approved = await this.#o.approvalStore.approve(input.record.id, {
        actor: "mcp-elicitation",
      });
      const consumed = await this.#o.approvalStore.consume(approved.id);
      return { kind: "approved", grant: grantFromApproval(consumed), mode: "elicitation" };
    }

    await this.#o.approvalStore.deny(input.record.id, {
      actor: "mcp-client",
      reason: result.action,
    });
    throw new GapError("Approval was declined.", {
      code: "APPROVAL_REQUIRED",
      details: { approvalId: input.record.id, status: "denied" },
    });
  }

  #approvalUrl(id: string, extra: ToolHandlerExtra): string {
    const base = this.#o.baseUrl ?? (extra.requestInfo?.url ? new URL("/", extra.requestInfo.url).origin : "");
    return `${base}/approvals/${encodeURIComponent(id)}`;
  }

  // ---------------------------------------------------------------------------
  // Built-in tools
  // ---------------------------------------------------------------------------

  #builtinAvailability(scopes: readonly string[]): {
    tasks: boolean;
    receipts: boolean;
    search: boolean;
    undo: boolean;
    handoff: boolean;
  } {
    const actions = this.registry.visibleTo(scopes);
    return {
      tasks: this.#o.enableTasks,
      receipts: true,
      search: actions.length > 12,
      undo: actions.some((action) => typeof action.undo === "function"),
      handoff: Boolean(this.#o.handoffSecret) && actions.some((action) => Boolean(action.ui)),
    };
  }

  #builtinAvailable(name: string, scopes: readonly string[]): boolean {
    const availability = this.#builtinAvailability(scopes);
    switch (name) {
      case "gap.tasks.get":
      case "gap.tasks.cancel":
        return availability.tasks;
      case "gap.receipts.get":
        return availability.receipts;
      case "gap.search":
        return availability.search;
      case "gap.undo":
        return availability.undo;
      case "gap.handoff":
        return availability.handoff;
      default:
        return false;
    }
  }

  async #handleBuiltin(
    name: string,
    args: Record<string, unknown>,
    auth: NormalizedAuth,
    extra: ToolHandlerExtra,
  ): Promise<CallToolResult> {
    const started = Date.now();
    const traceId = createId("trace");
    const callId = createId("rcpt");
    const tool = builtinDescriptor(name);
    const span = this.#span("gap.builtin", {
      "gap.action": name,
      "gap.trace_id": traceId,
      "gap.principal_id": auth.principal.id,
    });
    let argsHash: string | undefined;
    let auditDecision: AuditDecision = "error";
    let auditError: GapError | undefined;
    let outcome: BuiltinOutcome | undefined;

    try {
      if (!tool) throw new GapError(`Unknown tool "${name}".`, { code: "NOT_FOUND" });
      if (!this.#builtinAvailable(name, auth.scopes)) {
        throw new GapError(`Tool "${name}" is not available.`, { code: "NOT_FOUND" });
      }
      argsHash = await hashValue(args);
      const validation = validateValue(tool.inputSchema as JsonSchema, args);
      if (!validation.success) {
        throw new GapError(`Invalid input for "${name}".`, {
          code: "INVALID_INPUT",
          details: { issues: validation.issues },
        });
      }
      const input = validation.data as Record<string, unknown>;

      switch (name) {
        case "gap.tasks.get":
          outcome = await this.#builtinTasksGet(input, auth, traceId);
          break;
        case "gap.tasks.cancel":
          outcome = await this.#builtinTasksCancel(input, auth, traceId);
          break;
        case "gap.receipts.get":
          outcome = await this.#builtinReceiptsGet(input, auth, traceId);
          break;
        case "gap.search":
          outcome = this.#builtinSearch(input, auth, traceId);
          break;
        case "gap.undo":
          outcome = await this.#builtinUndo(input, auth, extra, traceId);
          break;
        case "gap.handoff":
          outcome = await this.#builtinHandoff(input, auth, extra, traceId);
          break;
        default:
          throw new GapError(`Tool "${name}" is not available.`, { code: "NOT_FOUND" });
      }

      const receipt = outcome.receipt ?? receiptMetaFromResult(outcome.response);
      auditDecision = "allowed";
      this.#recordCall(
        this.#callRecord({
          id: callId,
          action: name,
          auth,
          status: "success",
          args: input,
          result: outcome.result,
          redactedResult: outcome.redactedResult ?? outcome.result,
          durationMs: Date.now() - started,
          receipt: receipt as CallReceipt | undefined,
          traceId,
          metadata: { builtin: true, ...(outcome.metadata ?? {}) },
        }),
      );
      return outcome.response;
    } catch (error) {
      const gap = normalizeError(error);
      const message = gap.expose ? gap.message : "Internal error.";
      this.#safeRecordException(span, error);
      auditError = gap;
      auditDecision = auditDecisionForError(gap.code);
      this.#recordCall(
        this.#callRecord({
          id: callId,
          action: name,
          auth,
          status: "error",
          args,
          error: { code: gap.code, message, details: gap.expose ? gap.details : undefined },
          durationMs: Date.now() - started,
          traceId,
          metadata: { builtin: true },
        }),
      );
      return errorResult(gap, traceId);
    } finally {
      await this.#emitAudit({
        action: name,
        auth,
        decision: auditDecision,
        argsHash,
        durationMs: Date.now() - started,
        error: auditError,
        traceId,
        metadata: { builtin: true, ...(outcome?.metadata ?? {}) },
      });
      this.#safeEndSpan(span);
    }
  }

  #builtinSearch(
    input: Record<string, unknown>,
    auth: NormalizedAuth,
    traceId: string,
  ): BuiltinOutcome {
    const query = input.query;
    if (typeof query !== "string" || query.trim().length === 0) {
      throw new GapError("A query is required.", { code: "INVALID_INPUT" });
    }
    const limit = typeof input.limit === "number" ? input.limit : 10;
    const results = searchActions(this.registry, query, {
      scopes: auth.scopes,
      limit,
    }).map((result) => ({
      name: result.action.name,
      description: result.action.description,
      risk: result.action.risk ?? "low",
      scopes: result.action.scopes ?? [],
      score: result.score,
    }));
    const payload = { query, total: results.length, results };
    return { response: successResult({ value: payload, traceId }), result: payload };
  }

  async #builtinTasksGet(
    input: Record<string, unknown>,
    auth: NormalizedAuth,
    traceId: string,
  ): Promise<BuiltinOutcome> {
    const taskId = input.taskId;
    if (typeof taskId !== "string" || taskId.length === 0) {
      throw new GapError("A taskId is required.", { code: "INVALID_INPUT" });
    }
    const task = this.tasks.get(taskId);
    if (!task || !isOwnedBy(task, auth)) {
      throw new GapError("Task not found.", { code: "NOT_FOUND" });
    }
    return {
      response: successResult({ value: task, traceId }),
      result: task,
      redactedResult: task,
      receipt: task.receipt,
      metadata: { taskId: task.id, taskStatus: task.status },
    };
  }

  async #builtinTasksCancel(
    input: Record<string, unknown>,
    auth: NormalizedAuth,
    traceId: string,
  ): Promise<BuiltinOutcome> {
    const taskId = input.taskId;
    if (typeof taskId !== "string" || taskId.length === 0) {
      throw new GapError("A taskId is required.", { code: "INVALID_INPUT" });
    }
    const existing = this.tasks.get(taskId);
    if (!existing || !isOwnedBy(existing, auth)) {
      throw new GapError("Task not found.", { code: "NOT_FOUND" });
    }
    const task = this.tasks.cancel(taskId);
    return {
      response: successResult({ value: task, traceId }),
      result: task,
      redactedResult: task,
      receipt: task.receipt,
      metadata: { taskId: task.id, taskStatus: task.status },
    };
  }

  async #builtinReceiptsGet(
    input: Record<string, unknown>,
    auth: NormalizedAuth,
    traceId: string,
  ): Promise<BuiltinOutcome> {
    const receiptId = input.receiptId;
    if (typeof receiptId !== "string" || receiptId.length === 0) {
      throw new GapError("A receiptId is required.", { code: "INVALID_INPUT" });
    }
    const call = this.calls.get(receiptId);
    if (!call || !call.receipt || !isOwnedBy(call, auth)) {
      throw new GapError("Receipt not found.", { code: "NOT_FOUND" });
    }
    const payload = {
      receipt: call.receipt,
      args: call.args,
      result: call.redactedResult ?? call.result,
      undoneAt: call.undoneAt,
      undoReceiptId: call.undoReceiptId,
    };
    return {
      response: successResult({ value: payload, traceId }),
      result: payload,
      redactedResult: payload,
      receipt: call.receipt,
      metadata: { receiptId: call.receipt.id },
    };
  }

  async #builtinUndo(
    input: Record<string, unknown>,
    auth: NormalizedAuth,
    extra: ToolHandlerExtra,
    traceId: string,
  ): Promise<BuiltinOutcome> {
    const receiptId = input.receiptId;
    if (typeof receiptId !== "string" || receiptId.length === 0) {
      throw new GapError("A receiptId is required.", { code: "INVALID_INPUT" });
    }
    const call = this.calls.get(receiptId);
    if (!call || !call.receipt || !isOwnedBy(call, auth)) {
      throw new GapError("Receipt not found.", { code: "NOT_FOUND" });
    }
    if (call.undoneAt) {
      throw new GapError("This receipt has already been undone.", {
        code: "CONFLICT",
        details: { receiptId, undoReceiptId: call.undoReceiptId },
      });
    }
    const action = this.registry.get(call.receipt.action);
    if (!action) {
      throw new GapError(`Action "${call.receipt.action}" is no longer registered.`, {
        code: "NOT_FOUND",
      });
    }
    if (typeof action.undo !== "function") {
      throw new GapError("This action does not define an undo handler.", { code: "INVALID_INPUT" });
    }

    const undoReceiptId = createId("rcpt");
    const undoStarted = Date.now();
    const undoTraceId = createId("trace");
    const undoSpan = this.#span("gap.undo", {
      "gap.action": action.name,
      "gap.trace_id": undoTraceId,
      "gap.undo_of": call.receipt.id,
    });
    const signal = timeoutSignal(action.timeoutMs ?? this.#o.timeoutMs, extra.signal);
    const logger = this.#o.logger.child?.({ tool: "gap.undo", traceId: undoTraceId }) ?? this.#o.logger;
    const ctx: ActionContext = {
      principal: auth.principal,
      scopes: [...auth.scopes],
      tenantId: auth.principal.tenantId,
      dryRun: false,
      approval: call.approval,
      signal,
      traceId: undoTraceId,
      span: undoSpan,
      logger,
      request: extra.requestInfo,
    };
    try {
      const work = Promise.resolve().then(() => action.undo?.(call.result, call.args, ctx));
      await withAbort(work, signal, () =>
        extra.signal.aborted ? "The undo was cancelled." : "The undo timed out.",
      );
      const undoResult = { undone: call.receipt.id };
      const receipt: CallReceipt = {
        id: undoReceiptId,
        action: action.name,
        principalId: auth.principal.id,
        tenantId: auth.principal.tenantId,
        createdAt: new Date().toISOString(),
        durationMs: Date.now() - undoStarted,
        argsHash: call.receipt.argsHash,
        resultHash: await hashValue(undoResult),
        undoable: false,
        approvalId: call.approvalId,
        traceId: undoTraceId,
        undoOf: call.receipt.id,
      };
      this.calls.markUndone(call.receipt.id, undoReceiptId);
      this.#recordCall(
        this.#callRecord({
          id: undoReceiptId,
          action: action.name,
          auth,
          status: "success",
          args: call.args,
          result: undoResult,
          redactedResult: undoResult,
          durationMs: Date.now() - undoStarted,
          receipt,
          approval: call.approval,
          approvalId: call.approvalId,
          traceId: undoTraceId,
          metadata: { undoOf: call.receipt.id },
        }),
      );
      await this.#emitAudit({
        action: action.name,
        auth,
        decision: "allowed",
        argsHash: call.receipt.argsHash,
        resultHash: receipt.resultHash,
        durationMs: Date.now() - undoStarted,
        approvalId: call.approvalId,
        traceId: undoTraceId,
        metadata: { undoOf: call.receipt.id, receiptId: undoReceiptId },
      });
      const payload = { undone: true, receipt, undoOf: call.receipt.id };
      return {
        response: successResult({ value: payload, receipt, traceId }),
        result: payload,
        redactedResult: payload,
        receipt,
        metadata: { receiptId: undoReceiptId, undoOf: call.receipt.id },
      };
    } catch (error) {
      const gap = normalizeError(error);
      this.#safeRecordException(undoSpan, error);
      await this.#emitAudit({
        action: action.name,
        auth,
        decision: "error",
        argsHash: call.receipt.argsHash,
        durationMs: Date.now() - undoStarted,
        error: gap,
        approvalId: call.approvalId,
        traceId: undoTraceId,
        metadata: { undoOf: call.receipt.id },
      });
      throw gap;
    } finally {
      this.#safeEndSpan(undoSpan);
    }
  }

  async #builtinHandoff(
    input: Record<string, unknown>,
    auth: NormalizedAuth,
    extra: ToolHandlerExtra,
    traceId: string,
  ): Promise<BuiltinOutcome> {
    const actionName = input.action;
    if (typeof actionName !== "string" || actionName.length === 0) {
      throw new GapError("An action is required.", { code: "INVALID_INPUT" });
    }
    const action = this.registry.get(actionName);
    if (!action) throw new GapError(`Unknown action "${actionName}".`, { code: "NOT_FOUND" });
    const missing = missingScopes(auth.scopes, action.scopes);
    if (missing.length > 0) {
      throw new GapError(`Missing required scope(s): ${missing.join(", ")}.`, {
        code: "FORBIDDEN",
        details: { missingScopes: missing },
      });
    }
    if (!action.ui || !this.#o.handoffSecret) {
      throw new GapError(`Action "${actionName}" has no UI binding.`, { code: "INVALID_INPUT" });
    }

    const rawArgs = isJsonObject(input.args) ? input.args : {};
    let handoffArgs: unknown = rawArgs;
    if (action.input) {
      const validation = validateValue(action.input, rawArgs);
      if (!validation.success) {
        throw new GapError(`Invalid arguments for "${actionName}".`, {
          code: "INVALID_INPUT",
          details: { issues: validation.issues },
        });
      }
      handoffArgs = validation.data;
    }

    const base = this.#o.baseUrl ?? (extra.requestInfo?.url ? new URL("/", extra.requestInfo.url).origin : "");
    const link = await createSignedHandoffLink({
      secret: this.#o.handoffSecret,
      action: action.name,
      args: handoffArgs,
      principalId: auth.principal.id,
      tenantId: auth.principal.tenantId,
      baseUrl: base,
      route: action.ui.route ?? "/",
      ttlMs: this.#o.handoffTtlMs,
    });
    const payload: HandoffLinkPayload = {
      action: action.name,
      url: link.url,
      expiresAt: link.expiresAt,
    };
    return {
      response: successResult({
        value: payload,
        traceId,
        structuredExtras: { token: link.token },
      }),
      result: payload,
      redactedResult: payload,
      metadata: { handoffAction: action.name },
    };
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  #createContext(
    auth: NormalizedAuth,
    extra: ToolHandlerExtra,
    traceId: string,
    span: Span,
    logger: Logger,
  ): ActionContext {
    return {
      principal: auth.principal,
      scopes: [...auth.scopes],
      tenantId: auth.principal.tenantId,
      dryRun: false,
      signal: extra.signal,
      traceId,
      span,
      logger,
      request: extra.requestInfo,
    };
  }

  async #evaluatePolicy(
    action: AnyAction,
    args: unknown,
    ctx: ActionContext,
  ): Promise<PolicyDecision> {
    try {
      const decision = await this.#o.policy.evaluate({ action, args, ctx });
      if (
        !decision ||
        (decision.decision !== "allow" &&
          decision.decision !== "deny" &&
          decision.decision !== "confirm")
      ) {
        return { decision: "deny", reason: "Policy returned an invalid decision.", code: "POLICY_DENIED" };
      }
      return decision;
    } catch (error) {
      this.#o.logger.error(
        "Policy evaluation failed; denying the call.",
        error instanceof Error ? error.message : String(error),
      );
      return { decision: "deny", reason: "Policy evaluation failed.", code: "POLICY_DENIED" };
    }
  }

  #validateOutput(action: AnyAction, value: unknown): unknown {
    if (!action.output) return value;
    const result = validateValue(action.output, value);
    if (result.success) return result.data;
    throw new GapError("The action returned a result that does not match its output schema.", {
      code: "INTERNAL",
      details: { issues: result.issues },
    });
  }

  async #createReceipt(input: {
    id: string;
    action: string;
    auth: NormalizedAuth;
    argsHash: string;
    result: unknown;
    durationMs: number;
    approvalId?: string;
    traceId: string;
  }): Promise<CallReceipt> {
    const action = this.registry.get(input.action);
    return {
      id: input.id,
      action: input.action,
      principalId: input.auth.principal.id,
      tenantId: input.auth.principal.tenantId,
      createdAt: new Date().toISOString(),
      durationMs: input.durationMs,
      argsHash: input.argsHash,
      resultHash: await hashValue(input.result),
      undoable: typeof action?.undo === "function",
      approvalId: input.approvalId,
      traceId: input.traceId,
    };
  }

  #callRecord(input: {
    id: string;
    action: string;
    auth: NormalizedAuth;
    status: CallStatus;
    args?: unknown;
    result?: unknown;
    redactedResult?: unknown;
    error?: { code: string; message: string; details?: unknown };
    durationMs: number;
    receipt?: CallReceipt;
    approval?: ApprovalGrant;
    approvalId?: string;
    traceId: string;
    taskId?: string;
    replayed?: boolean;
    metadata?: Record<string, unknown>;
  }): CallRecord {
    return {
      id: input.id,
      timestamp: new Date().toISOString(),
      action: input.action,
      principalId: input.auth.principal.id,
      tenantId: input.auth.principal.tenantId,
      status: input.status,
      args: input.args,
      result: input.result,
      redactedResult: input.redactedResult,
      error: input.error,
      durationMs: input.durationMs,
      receipt: input.receipt,
      approval: input.approval,
      approvalId: input.approvalId,
      traceId: input.traceId,
      taskId: input.taskId,
      replayed: input.replayed,
      metadata: input.metadata,
    };
  }

  #recordCall(record: CallRecord): void {
    this.calls.put(record);
    if (!this.#o.onCall) return;
    try {
      this.#o.onCall({
        ...record,
        result: record.redactedResult ?? record.result,
      });
    } catch (error) {
      this.#o.logger.warn(
        "onCall callback failed.",
        error instanceof Error ? error.message : String(error),
      );
    }
  }

  #replayOutcome(response: CallToolResult): RunOutcome {
    const receiptMeta = receiptMetaFromResult(response);
    if (response.isError) {
      const structured = response.structuredContent;
      const gapError = isJsonObject(structured) ? structured.gapError : undefined;
      return {
        response,
        decision: "error",
        status: "error",
        result: response.content,
        redactedResult: response.content,
        metadata: { replayed: true },
      };
    }
    const status =
      isJsonObject(response.structuredContent) && response.structuredContent.status === "approval_required"
        ? "approval_required"
        : "success";
    return {
      response,
      decision: status === "approval_required" ? "approval_required" : "allowed",
      status,
      result: response.structuredContent ?? response.content,
      redactedResult: response.structuredContent ?? response.content,
      ...(receiptMeta ? { metadata: { receiptId: receiptMeta.id } } : {}),
    };
  }

  async #emitAudit(input: {
    action: string;
    auth: NormalizedAuth;
    decision: AuditDecision;
    argsHash?: string;
    resultHash?: string;
    durationMs: number;
    error?: GapError;
    approvalId?: string;
    traceId: string;
    metadata?: Record<string, unknown>;
  }): Promise<void> {
    if (!this.#o.audit) return;
    const event: AuditEvent = {
      id: createId("audit"),
      timestamp: new Date().toISOString(),
      action: input.action,
      principalId: input.auth.principal.id,
      tenantId: input.auth.principal.tenantId,
      decision: input.decision,
      ...(input.argsHash ? { argsHash: input.argsHash } : {}),
      ...(input.resultHash ? { resultHash: input.resultHash } : {}),
      durationMs: input.durationMs,
      scopes: [...input.auth.scopes],
      ...(input.approvalId ? { approvalId: input.approvalId } : {}),
      traceId: input.traceId,
      ...(input.error
        ? {
            error: {
              code: input.error.code,
              message: input.error.expose ? input.error.message : "Internal error.",
            },
          }
        : {}),
      ...(input.metadata ? { metadata: input.metadata } : {}),
    };
    try {
      await this.#o.audit.record(event);
    } catch (error) {
      this.#o.logger.warn(
        "Audit sink failed.",
        error instanceof Error ? error.message : String(error),
      );
    }
  }

  #span(name: string, attributes: Record<string, unknown>): Span {
    try {
      return this.#o.tracer.startSpan(name, attributes);
    } catch {
      return NOOP_SPAN;
    }
  }

  #safeEndSpan(span: Span): void {
    try {
      span.end();
    } catch {
      // A tracer must not break a tool call.
    }
  }

  #safeRecordException(span: Span, error: unknown): void {
    try {
      span.recordException(error);
    } catch {
      // A tracer must not break a tool call.
    }
  }

  #warnOnce(key: string, message: string): void {
    if (this.#warned.has(key)) return;
    this.#warned.add(key);
    this.#o.logger.warn(message);
  }
}

function syntheticGrant(action: AnyAction, name: string, argsHash: string): ApprovalGrant {
  return {
    id: `apr_${name}`,
    action: name,
    argsHash,
    approvedBy: "implicit",
    issuedAt: 0,
    expiresAt: Number.MAX_SAFE_INTEGER,
  };
}

/**
 * Create a {@link GapServer} without starting a transport. Call `fetch`,
 * `handleNode` or `connect` to attach it to a transport.
 */
export function createGapServer(options: GapServerOptions): GapServer {
  return new GapServer(options);
}
