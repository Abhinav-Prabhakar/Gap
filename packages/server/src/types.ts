import type {
  ActionContext,
  AnyAction,
  ApprovalGate,
  ApprovalGrant,
  AuditSink,
  AuthProvider,
  JsonSchema,
  Logger,
  PolicyEngine,
  Principal,
  Tracer,
} from "gapmcp-core";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";

/** Lifecycle of a human approval request. */
export type ApprovalStatus = "pending" | "approved" | "denied" | "consumed" | "expired";

/**
 * One approval request. Records are keyed by
 * `(principalId, tenantId, action, argsHash)` while pending or approved so an
 * agent retrying the same invocation finds the same approval instead of
 * creating a queue of duplicates.
 */
export interface ApprovalRecord {
  id: string;
  principalId: string;
  tenantId?: string;
  action: string;
  /** Stable hash of the exact arguments the human is approving. */
  argsHash: string;
  status: ApprovalStatus;
  createdAt: number;
  expiresAt: number;
  /** The arguments to display to the approver. Never returned to the agent by the server. */
  args?: unknown;
  approvedAt?: number;
  approvedBy?: string;
  deniedAt?: number;
  deniedBy?: string;
  reason?: string;
  consumedAt?: number;
  metadata?: Record<string, unknown>;
}

/** Input accepted by {@link ApprovalStore.create}. */
export interface CreateApprovalInput {
  principalId: string;
  tenantId?: string;
  action: string;
  argsHash: string;
  args?: unknown;
  ttlMs?: number;
  metadata?: Record<string, unknown>;
}

/** Filter accepted by {@link ApprovalStore.list}. */
export interface ApprovalFilter {
  principalId?: string;
  tenantId?: string;
  action?: string;
  argsHash?: string;
  status?: ApprovalStatus | readonly ApprovalStatus[];
}

/** Options for approving or denying a request. */
export interface ResolveApprovalOptions {
  /** Identity of the approver. Defaults to `"unknown"`. */
  actor?: string;
  /** Human-readable denial reason. */
  reason?: string;
}

/**
 * Storage for pending and resolved approvals. Implement this to share
 * approvals across processes; the default implementation is
 * {@link MemoryApprovalStore}.
 */
export interface ApprovalStore {
  create(input: CreateApprovalInput): ApprovalRecord | Promise<ApprovalRecord>;
  get(id: string): ApprovalRecord | undefined | Promise<ApprovalRecord | undefined>;
  list(filter?: ApprovalFilter): ApprovalRecord[] | Promise<ApprovalRecord[]>;
  approve(id: string, options?: ResolveApprovalOptions): ApprovalRecord | Promise<ApprovalRecord>;
  deny(id: string, options?: ResolveApprovalOptions): ApprovalRecord | Promise<ApprovalRecord>;
  /**
   * Atomically transition an approved request to `consumed`. Only one caller
   * may consume a given approval.
   */
  consume(id: string): ApprovalRecord | Promise<ApprovalRecord>;
}

/** Result of one rate-limit accounting operation. */
export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  retryAfterMs: number;
  /** Epoch milliseconds at which the request may succeed. */
  resetAt: number;
}

/**
 * Per-key rate limiter. The server keys calls by `principalId:toolName`, so a
 * noisy agent cannot starve other principals or other tools.
 */
export interface RateLimiter {
  consume(key: string, cost?: number): RateLimitResult | Promise<RateLimitResult>;
  reset?(key?: string): void;
}

/** A cached tool result keyed by an idempotency key. */
export interface IdempotencyRecord<T = unknown> {
  key: string;
  value: T;
  createdAt: number;
  expiresAt: number;
}

/** Storage for idempotent tool results. */
export interface IdempotencyStore {
  get(key: string): IdempotencyRecord | undefined | Promise<IdempotencyRecord | undefined>;
  set(key: string, record: IdempotencyRecord): void | Promise<void>;
  delete?(key: string): void | Promise<void>;
}

/** Audit/UI receipt for one completed action invocation. */
export interface CallReceipt {
  id: string;
  action: string;
  principalId: string;
  tenantId?: string;
  createdAt: string;
  durationMs: number;
  argsHash: string;
  resultHash: string;
  undoable: boolean;
  dryRun?: boolean;
  approvalId?: string;
  traceId: string;
  /** Set when this receipt represents an undo of an earlier receipt. */
  undoOf?: string;
}

/** Status stored on a {@link CallRecord}. */
export type CallStatus = "success" | "error" | "approval_required" | "task" | "dry_run";

/** Error shape surfaced through tool results. */
export interface GapErrorPayload {
  code: string;
  message: string;
  retryable: boolean;
  details?: unknown;
}

/**
 * One tool invocation, suitable for an inspector or a `gap.calls` view. The
 * raw `args`/`result` are available to trusted in-process consumers; `onCall`
 * receives a copy whose result is already redacted.
 */
export interface CallRecord {
  id: string;
  timestamp: string;
  action: string;
  principalId: string;
  tenantId?: string;
  status: CallStatus;
  args?: unknown;
  /** The validated value the action produced, before policy redaction. */
  result?: unknown;
  /** The value returned to the client after policy redaction. */
  redactedResult?: unknown;
  error?: { code: string; message: string; details?: unknown };
  durationMs: number;
  receipt?: CallReceipt;
  approval?: ApprovalGrant;
  approvalId?: string;
  traceId: string;
  taskId?: string;
  replayed?: boolean;
  undoneAt?: string;
  undoReceiptId?: string;
  metadata?: Record<string, unknown>;
}

/** Status of a background task. */
export type TaskStatus = "working" | "completed" | "failed" | "cancelled";

/** A background action invocation created for an action with `task: true`. */
export interface TaskRecord {
  id: string;
  action: string;
  principalId: string;
  tenantId?: string;
  status: TaskStatus;
  createdAt: string;
  updatedAt: string;
  input?: unknown;
  result?: unknown;
  error?: { code: string; message: string };
  receipt?: CallReceipt;
  traceId: string;
  approvalId?: string;
  /** The CallStore record this task updates when it settles. */
  callId?: string;
}

/** Payload returned to an agent when a call is waiting for human approval. */
export interface ApprovalRequiredPayload {
  status: "approval_required";
  action: string;
  approvalId: string;
  approveUrl: string;
  retry: true;
  argsHash: string;
  expiresAt: string;
}

/** Payload returned when a task-backed action is accepted. */
export interface TaskStartedPayload {
  status: "working";
  taskId: string;
  action: string;
}

/** Payload returned by `gap.handoff`. */
export interface HandoffLinkPayload {
  action: string;
  url: string;
  expiresAt: number;
}

/** CORS policy for the HTTP transport. */
export interface CorsOptions {
  /**
   * Allowed origins. `"*"` reflects any origin; a string or array is matched
   * exactly; a function decides. Defaults to `"*"`.
   */
  origin?: string | string[] | ((origin: string) => boolean);
  allowHeaders?: string[];
  exposeHeaders?: string[];
  allowMethods?: string[];
  /** Preflight cache lifetime in seconds. Defaults to one day. */
  maxAge?: number;
  /** Send `Access-Control-Allow-Credentials`. Reflects the origin when true. */
  credentials?: boolean;
}

/** HTTP-specific options accepted alongside {@link GapServerOptions}. */
export interface HttpServerOptions {
  /** Route for the MCP endpoint. Defaults to `/mcp`. */
  path?: string;
  /** Route for RFC 9728 metadata. Defaults to `/.well-known/oauth-protected-resource`. */
  protectedResourcePath?: string;
  /** Route for the health probe. Defaults to `/health`. */
  healthPath?: string;
  /** CORS policy, or `false` to emit no CORS headers. Defaults to permissive CORS. */
  cors?: boolean | CorsOptions;
  /** Host header values accepted by the DNS-rebinding guard. */
  allowedHosts?: string[];
  /** Origin header values accepted. Same-origin requests are always accepted. */
  allowedOrigins?: string[];
  /**
   * Reject requests whose `Host`/`Origin` headers do not belong to this server.
   * Defaults to `true`; localhost, loopback and the configured base URL are
   * trusted automatically.
   */
  enableDnsRebindingProtection?: boolean;
  /** Return JSON responses instead of SSE for POST requests. Defaults to `false`. */
  enableJsonResponse?: boolean;
  /** Maximum POST body size in bytes. Defaults to the SDK's 4 MiB. */
  maxRequestBodySize?: number;
  /** SSE keep-alive interval in milliseconds. Defaults to the SDK's 15 seconds. */
  keepAliveMs?: number;
}

/** Options accepted by {@link GapServer}. */
export interface GapServerOptions extends HttpServerOptions {
  registry: import("gapmcp-core").ActionRegistry;
  /** MCP implementation name. Defaults to `"gap"`. */
  name?: string;
  /** MCP implementation version. Defaults to the core package version. */
  version?: string;
  /** Instructions sent to clients during initialization. */
  instructions?: string;
  /** Authenticates HTTP requests. Without one, requests run anonymously. */
  auth?: AuthProvider;
  /** Policy engine. Defaults to allow-all. */
  policy?: PolicyEngine;
  /** Tracing implementation. Defaults to a no-op tracer. */
  tracer?: Tracer;
  /** Audit sink. Audit events never contain raw arguments or results. */
  audit?: AuditSink;
  /** Structured logger. Defaults to warnings and errors only. */
  logger?: Logger;
  /** Optional HMAC approval-token issuer and verifier. */
  approvals?: ApprovalGate;
  /** Pending approval storage. Defaults to an in-memory store. */
  approvalStore?: ApprovalStore;
  /** Per-principal-per-tool rate limit, or a custom limiter. */
  rateLimit?: { limit: number; windowMs: number } | RateLimiter;
  /** Idempotency result storage. Defaults to an in-memory store. */
  idempotency?: IdempotencyStore;
  /** Session handling for Streamable HTTP. Defaults to `"stateful"`. */
  sessionMode?: "stateful" | "stateless";
  /** Absolute base URL used in approval and handoff links. */
  baseUrl?: string;
  /** Ask the client through MCP elicitation before falling back to the approval queue. */
  allowElicitation?: boolean;
  /** Secret used to sign `gap.handoff` state tokens. Enables the handoff tool. */
  handoffSecret?: string;
  /** Expose `gap.tasks.get` / `gap.tasks.cancel`. Defaults to `true`. */
  enableTasks?: boolean;
  /** Number of calls retained by {@link CallStore}. Defaults to 500. */
  callStoreLimit?: number;
  /** Called for every call with an inspector-friendly record. */
  onCall?: (record: CallRecord) => void;
  /**
   * Permit unauthenticated HTTP requests. Defaults to `true` only when no auth
   * provider is configured. With an auth provider, a failed authentication is
   * rejected unless this is explicitly true.
   */
  allowAnonymous?: boolean;
  /** Extra dot paths to redact from every successful result. */
  redact?: string[];
  /** Default action execution budget in milliseconds. Defaults to 30 seconds. */
  timeoutMs?: number;
  /** Lifetime of a pending approval. Defaults to 5 minutes. */
  approvalTtlMs?: number;
  /** Lifetime of a signed handoff state token. Defaults to 10 minutes. */
  handoffTtlMs?: number;
}

/** A tool call result as consumed by the server pipeline. */
export type GapToolResult = CallToolResult;

/** A tool descriptor as exposed over MCP. */
export type GapToolDescriptor = Tool;

/** Options for an isolated {@link TaskManager}. */
export interface TaskManagerOptions {
  /** Maximum retained task records. Defaults to 1000. */
  maxTasks?: number;
  /** Clock injection for tests. */
  now?: () => number;
  /** How long `close()` waits for aborted tasks to settle. Defaults to 5 seconds. */
  closeTimeoutMs?: number;
}

/** Snapshot of an action context used while a task runs in the background. */
export type TaskActionContext = ActionContext;

/** Untyped action alias used internally by the pipeline. */
export type PipelineAction = AnyAction;

/** JSON object helper used by public result payloads. */
export type JsonObject = Record<string, unknown>;

/** A JSON Schema object. Re-exported for convenience. */
export type GapJsonSchema = JsonSchema;
