import type { ZodType } from "zod";

/** A JSON Schema object (draft 2020-12 compatible). */
export type JsonSchema = Record<string, unknown>;

/** Either a Zod schema or a plain JSON Schema object. */
export type SchemaLike = ZodType | JsonSchema;

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type PrincipalType = "user" | "service" | "anonymous";

/**
 * The identity an action runs as. Gap never uses ambient service credentials:
 * every invocation carries the principal the action is executed for.
 */
export interface Principal {
  id: string;
  type?: PrincipalType;
  tenantId?: string;
  scopes?: string[];
  email?: string;
  name?: string;
  metadata?: Record<string, unknown>;
}

export interface AuthResult {
  principal: Principal;
  token?: string;
  clientId?: string;
  scopes?: string[];
  expiresAt?: number;
  extra?: Record<string, unknown>;
}

/** A signed grant proving a human approved one specific action invocation. */
export interface ApprovalGrant {
  id: string;
  action: string;
  argsHash: string;
  approvedBy: string;
  issuedAt: number;
  expiresAt: number;
  scope?: string;
}

export interface ApprovalRequest {
  action: string;
  args: unknown;
  principalId: string;
  ttlMs?: number;
}

export interface IssuedApproval {
  token: string;
  grant: ApprovalGrant;
}

/**
 * Issues and verifies approval tokens. Implementations must bind the token to
 * a hash of the exact arguments so an agent cannot swap the payload after a
 * human approves it.
 */
export interface ApprovalGate {
  issue(request: ApprovalRequest): IssuedApproval | Promise<IssuedApproval>;
  verify(
    token: string,
    request: Omit<ApprovalRequest, "ttlMs">,
  ): ApprovalGrant | null | Promise<ApprovalGrant | null>;
}

/** Transport-agnostic authentication for a web `Request`. */
export interface AuthProvider {
  authenticate(request: Request): AuthResult | null | Promise<AuthResult | null>;
  /** Value for the WWW-Authenticate header on a 401. */
  challenge?(): string;
  /** RFC 9728 protected resource metadata document. */
  protectedResourceMetadata?(): Record<string, unknown>;
}

export interface TraceContext {
  traceId: string;
  spanId?: string;
  parentSpanId?: string;
}

export interface Logger {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
  child?(bindings: Record<string, unknown>): Logger;
}

export interface Span {
  setAttribute(key: string, value: string | number | boolean): void;
  setAttributes(attributes: Record<string, unknown>): void;
  recordException(error: unknown): void;
  end(): void;
}

export interface Tracer {
  startSpan(name: string, attributes?: Record<string, unknown>): Span;
}

export type AuditDecision =
  | "allowed"
  | "denied"
  | "error"
  | "approval_required"
  | "dry_run";

export interface AuditEvent {
  id: string;
  timestamp: string;
  action: string;
  principalId: string;
  tenantId?: string;
  decision: AuditDecision;
  argsHash?: string;
  resultHash?: string;
  durationMs?: number;
  scopes?: string[];
  approvalId?: string;
  traceId?: string;
  error?: { code: string; message: string };
  metadata?: Record<string, unknown>;
}

export interface AuditSink {
  record(event: AuditEvent): void | Promise<void>;
}

export interface PolicyDecision {
  decision: "allow" | "deny" | "confirm";
  reason?: string;
  code?: string;
  redactPaths?: string[];
  limits?: Record<string, number>;
  metadata?: Record<string, unknown>;
}

export interface PolicyEvaluationInput {
  action: AnyAction;
  args: unknown;
  ctx: ActionContext;
}

export interface PolicyEngine {
  evaluate(
    input: PolicyEvaluationInput,
  ): PolicyDecision | Promise<PolicyDecision>;
}

export interface ActionContext<P extends Principal = Principal> {
  principal: P;
  scopes: string[];
  tenantId?: string;
  dryRun: boolean;
  idempotencyKey?: string;
  approval?: ApprovalGrant;
  signal: AbortSignal;
  traceId: string;
  span?: Span;
  logger: Logger;
  /** The framework request, when the action was reached through an adapter. */
  request?: unknown;
  /** Application-provided services, passed through untouched. */
  services?: Record<string, unknown>;
}

export interface ActionUiBinding {
  /** Deep link into the app's UI for human handoff. */
  route?: string;
  /** Value written to data-gap-action on the root element. */
  action?: string;
  /** Argument name -> CSS selector for the input that carries it. */
  fields?: Record<string, string>;
  /** CSS selector for the element that submits the flow. */
  submit?: string;
  /** CSS selector whose text is the action result. */
  result?: string;
  /** CSS selector that must appear before the flow is considered done. */
  waitFor?: string;
}

export interface ActionExample<I = unknown> {
  input: I;
  description?: string;
}

export interface ActionAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface ActionDefinition<I = unknown, O = unknown> {
  /** Stable, dot-namespaced tool name, e.g. `invoices.create`. */
  name: string;
  /** Monotonic contract version. Exposed in tool metadata. */
  version?: number;
  title?: string;
  /** Written for the model, not for a human. Be precise about side effects. */
  description: string;
  input?: SchemaLike;
  output?: SchemaLike;
  /** OAuth-style scopes required. Empty means public to authenticated principals. */
  scopes?: string[];
  risk?: RiskLevel;
  idempotent?: boolean;
  /** Ask a human before running. A function can decide per invocation. */
  confirm?: boolean | ((input: I, ctx: ActionContext) => boolean | Promise<boolean>);
  tags?: string[];
  examples?: ActionExample<I>[];
  annotations?: ActionAnnotations;
  ui?: ActionUiBinding;
  /** Best-effort inverse for mutations. Surfaced as a receipt/undo affordance. */
  undo?: (output: O, input: I, ctx: ActionContext) => void | Promise<void>;
  execute: (input: I, ctx: ActionContext) => O | Promise<O>;
  /** Framework metadata. Never expose secret values here. */
  meta?: Record<string, unknown>;
  /** Per-action execution budget. */
  timeoutMs?: number;
  /** Run as a pollable background task instead of holding the tool call open. */
  task?: boolean;
  /** Deprecation notice surfaced to clients. */
  deprecated?: boolean | string;
}

export interface ToolDescriptor {
  name: string;
  title?: string;
  description: string;
  inputSchema: JsonSchema;
  outputSchema?: JsonSchema;
  annotations?: ActionAnnotations;
  _meta?: Record<string, unknown>;
}

export type AnyAction = ActionDefinition<any, any>;

export interface RegistryIssue {
  level: "error" | "warn";
  code: string;
  action?: string;
  message: string;
}

export interface ActionFilter {
  names?: string[];
  namespace?: string;
  tags?: string[];
  scopes?: string[];
  include?: (action: AnyAction) => boolean;
}

export interface ToolDescriptorOptions {
  scopes?: string[];
  filter?: ActionFilter;
}

export type ValidationIssue = {
  path: string;
  message: string;
  code?: string;
};

export type ValidationResult<T = unknown> =
  | { success: true; data: T }
  | { success: false; issues: ValidationIssue[] };
