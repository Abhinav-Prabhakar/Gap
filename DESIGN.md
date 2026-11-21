# Gap — design and module contracts

Gap is a typed action layer for agents. One action definition compiles to an MCP
tool, an OpenAPI operation and a semantic DOM binding, and runs through one
policy / auth / audit pipeline. This document is the integration contract
between packages. Read `packages/core` before writing code.

## Package map

| Package | Purpose |
| --- | --- |
| `gapmcp-core` | Action contract, registry, schema conversion, errors, shared types |
| `gapmcp-auth` | API key + JWT auth, OAuth metadata, approval tokens, audit sinks |
| `gapmcp-policy` | Policy-as-code: deny/confirm/limits/redaction/dry-run |
| `gapmcp-observability` | Tracers, recorded calls, replay |
| `gapmcp-server` | MCP server, transports, pipeline, approvals, tasks, receipts |
| `gapmcp-importers` | OpenAPI and Next.js route importers |
| `gapmcp-dom` | DOM manifest, browser runtime, signed handoff links |
| `gapmcp-evals` | Tool-selection evals, confusion matrix, description linter |
| `gapmcp-testing` | Test harness for actions and servers |
| `gapmcp-cli` | `gap` CLI and local inspector |
| `gapmcp` | Umbrella package with subpath exports |

## Non-negotiables

- ESM, `"type": "module"`, TypeScript strict, Node >= 20.
- Zod 4 for schemas; plain JSON Schema must also work (see `gapmcp-core`).
- No new runtime dependencies without checking the root `package.json` first.
  Everything needed is already installed; do not run `pnpm install`.
- Tests use Vitest in `packages/<pkg>/test/*.test.ts`. Run from the repo root:
  `./node_modules/.bin/vitest run packages/<pkg>`.
- Typecheck: `./node_modules/.bin/tsc -p packages/<pkg>/tsconfig.json --noEmit`.
- Do not edit root configs, other packages, `README.md`, or `.github/`.
- Never add CI workflows. Never log secrets, tokens or raw PII.
- Public functions need doc comments. Errors crossing a boundary must be
  `GapError` (from core). Everything must be deterministic and testable.

## Cross-package types (already in core)

`AnyAction`, `ActionContext`, `Principal`, `AuthResult`, `AuthProvider`,
`ApprovalGate`, `ApprovalGrant`, `PolicyEngine`, `PolicyDecision`, `AuditSink`,
`AuditEvent`, `Tracer`, `Span`, `Logger`, `ToolDescriptor`, `JsonSchema`.

Use these; do not redefine them.

## `gapmcp-auth`

```ts
export interface ApiKeyRecord { key: string; principal: Principal; scopes?: string[] }
export function apiKeyAuth(options: {
  keys: ApiKeyRecord[] | ((request: Request) => ApiKeyRecord | undefined | Promise<...>);
  header?: "authorization" | "x-api-key";
}): AuthProvider;

export function jwtAuth(options: {
  issuer?: string; audience?: string | string[];
  jwksUri?: string; jwks?: Record<string, unknown>;
  clockToleranceSeconds?: number;
  mapClaims?: (claims: Record<string, unknown>) => Principal | null;
}): AuthProvider;

export function composeAuth(...providers: AuthProvider[]): AuthProvider;
export function protectedResourceMetadata(options: {
  resource: string; authorizationServers: string[]; scopesSupported?: string[];
}): Record<string, unknown>;
export function bearerChallenge(options?: { realm?: string; error?: string; resourceMetadataUrl?: string }): string;

export class HmacApprovalGate implements ApprovalGate {
  constructor(options: { secret: string | Uint8Array; ttlMs?: number; now?: () => number });
}

export function exchangeToken(options: {
  tokenEndpoint: string; subjectToken: string; subjectTokenType?: string;
  audience?: string; scope?: string[]; clientId?: string; clientSecret?: string;
  fetch?: typeof fetch;
}): Promise<{ accessToken: string; expiresIn?: number; tokenType: string; scope?: string }>;

export class MemoryAuditLog implements AuditSink { events: AuditEvent[]; list(): AuditEvent[]; clear(): void }
export class JsonlAuditLog implements AuditSink { constructor(path: string); close(): Promise<void> }
```

JWT: use `jose`, verify signature, issuer, audience, expiry, and map standard
claims (`sub`, `scope`/`scp`, `tenant_id`, `email`, `name`). Reject otherwise.
API key: constant-time comparison, accept `Bearer <key>` or `X-API-Key`.
Approval tokens: compact `v1.<base64url payload>.<hmac>` with `id`, `action`,
`argsHash`, `approvedBy`, `iat`, `exp`, `nonce`; verify re-hashes args and checks
expiry. Never compare secrets with `===`.

## `gapmcp-policy`

```ts
export interface PolicyRule {
  tools?: string[];        // glob-ish: "invoices.*" or exact
  deny?: boolean; confirm?: boolean; dryRun?: boolean;
  maxAmount?: number; amountPaths?: string[];
  maxArrayLength?: number; arrayPaths?: string[];
  redact?: string[];
  reason?: string;
}
export interface PolicyDocument {
  version: 1; default?: "allow" | "deny"; rules: PolicyRule[];
  redact?: string[]; confirm?: string[]; deny?: string[];
}
export function definePolicy(document: PolicyDocument): PolicyDocument;
export function parsePolicy(input: string | PolicyDocument): PolicyDocument; // JSON
export class GapPolicy implements PolicyEngine { constructor(input: PolicyDocument | string); }
```

Evaluation: first matching deny wins; confirm if any matching rule confirms; else
allow. Limits inspect numeric paths (default amount paths: `amount`, `total`,
`value`, `price`, `cost`) and arrays (default: any array) recursively. A limit
violation returns `{decision:"deny", code:"LIMIT_EXCEEDED"}`. Redactions merge
across matching rules. `dryRun` sets `ctx.dryRun = true`. Unit-test matching,
limits, nested arrays, redaction merge, dry-run.

## `gapmcp-observability`

```ts
export class MemoryTracer implements Tracer { spans: RecordedSpan[]; clear(): void }
export class ConsoleTracer implements Tracer { constructor(logger?: Logger) }
export function otelTracer(tracer: import("@opentelemetry/api").Tracer): Tracer;
export interface RecordedCall { id; timestamp; action; args; result?; error?; principalId; tenantId?; durationMs }
export class ReplayRecorder {
  constructor(options?: { redact?: string[] });
  record(call: Omit<RecordedCall, "id" | "timestamp">): RecordedCall;
  entries(): RecordedCall[];
  toJSON(): string;
  static fromJSON(json: string): ReplayRecorder;
  replay(registry: ActionRegistry, options?: { principal?: Principal; dryRun?: boolean }): Promise<ReplayResult[]>;
}
```

`MemoryTracer` records name, attributes, status, start/end. `otelTracer` wraps a
real OTel tracer; keep `@opentelemetry/api` as a type-only dependency at runtime.

## `gapmcp-server`

The centrepiece. Public API (exact names matter to CLI/tests):

```ts
export interface GapServerOptions {
  registry: ActionRegistry;
  name?: string; version?: string; instructions?: string;
  auth?: AuthProvider;                 // default: anonymous principal with ["*"] (dev only)
  policy?: PolicyEngine;               // default: allow all
  tracer?: Tracer; audit?: AuditSink; logger?: Logger;
  approvals?: ApprovalGate;            // HMAC tokens, optional
  approvalStore?: ApprovalStore;       // pending approvals, default in-memory
  rateLimit?: { limit: number; windowMs: number } | RateLimiter;
  idempotency?: IdempotencyStore;
  sessionMode?: "stateful" | "stateless";
  baseUrl?: string;                    // links in approval / receipt results
  allowElicitation?: boolean;          // use MCP elicitation for confirmations
  handoffSecret?: string;              // adds gap.handoff when set
  enableTasks?: boolean;               // default true
  callStoreLimit?: number;             // default 500
  onCall?: (record: CallRecord) => void;
}
export class GapServer {
  constructor(options: GapServerOptions);
  fetch(request: Request): Promise<Response>;
  handleNode(req: IncomingMessage, res: ServerResponse): Promise<void>;
  connect(transport: Transport): Promise<void>;
  close(): Promise<void>;
  readonly registry: ActionRegistry;
  readonly calls: CallStore;
}
export function createGapServer(options): GapServer;
export function createNodeHandler(options): (req, res) => Promise<void>;
export function createFetchHandler(options): (req: Request) => Promise<Response>;
export function createStdioServer(options): Promise<{ close(): Promise<void> }>;
```

Also export `MemoryIdempotencyStore`, `TokenBucketRateLimiter`,
`MemoryApprovalStore`, `TaskManager`, `CallStore`.

Pipeline: auth -> scope check -> policy -> rate limit -> input validation ->
approval (store or elicitation) -> execute with timeout -> output validation ->
redaction -> audit -> receipt. `listTools` must only return actions visible to
the principal's scopes. Tool results need both `content` text and
`structuredContent` when the action has an output schema. Errors become
`isError: true` with text plus `structuredContent.gapError` (code, message,
retryable, details when safe).

Approvals: if `confirm` is required and there is no approval for
`(principalId, action, argsHash)`, create a pending record and return
`{status:"approval_required", approvalId, approveUrl, retry:true}`. A retry after
`approve(id)` executes. If `allowElicitation` and the client supports it, ask
through MCP elicitation first. Also accept `params._meta["gap/approval"]` as an
HMAC token when `approvals` is configured.

Tasks: actions with `task: true` return `{taskId, status:"working"}` and run in
the background. Expose `gap.tasks.get` and `gap.tasks.cancel` when enabled.
Receipts: every successful call stores a receipt; expose `gap.receipts.get` and
`gap.undo` (when the action has `undo`). Handoff: expose `gap.handoff` for
actions with `ui`, using a signed state token.

HTTP: `POST/GET/DELETE /mcp` via `WebStandardStreamableHTTPServerTransport`,
`GET /.well-known/oauth-protected-resource`, `GET /health`. Stateful sessions
are keyed by `Mcp-Session-Id`; stateless mode creates a server per request.
Node adapter must stream SSE responses, not buffer them. CORS + DNS-rebinding
guard are on by default; allow config.

Test with the SDK client (`Client` + `StreamableHTTPClientTransport`) against a
real ephemeral HTTP server. Cover at least: list visibility, successful call,
invalid input, 401, scope denial, policy denial, approval approve+retry, rate
limit, idempotency replay, output redaction, task polling, receipt/undo,
`gap.handoff`, and audit events.

## `gapmcp-importers`

```ts
export function parseOpenApiSpec(input: string | object): Record<string, any>;
export async function importOpenApi(options: {
  spec: string | object; baseUrl?: string; include?: (op: OpenApiOperation) => boolean;
  fetch?: typeof fetch; headers?: Record<string, string>;
}): Promise<AnyAction[]>;
export async function scanNextRoutes(options: { dir: string; baseUrl?: string }): Promise<AnyAction[]>;
```

OpenAPI: local `$ref` resolution only, path/query/header/body params, operationId
or `<method>.<sanitized path>`, description from summary + description, output
schema from the first 2xx JSON response, risk by method, DELETE high+confirm.
`execute` performs the HTTP request via injected `fetch`; non-2xx throws
`GapError`. Next: walk `app/**/route.ts`, detect exported methods with a regex,
build paths from folders (`[id]` -> `:id`); if `baseUrl` is set, the action
proxies to it, otherwise `execute` throws a clear "wire this up" error. Tests
use fixtures under `test/fixtures`.

## `gapmcp-dom`

```ts
export interface DomActionBinding { name; scopes; risk; ui: ActionUiBinding }
export interface DomManifest { version: 1; generatedAt: string; actions: DomActionBinding[] }
export function buildDomManifest(registry: ActionRegistry, options?: { include?: string[] }): DomManifest;
export function renderDomRuntime(options?: { globalName?: string; timeoutMs?: number }): string;
export function renderDomScriptTag(options?): string;
export function createHandoffUrl(options: {
  baseUrl: string; action: string; args: unknown; secret: string;
  ttlMs?: number; path?: string;
}): Promise<string>;
export function verifyHandoffState(token: string, secret: string): Promise<HandoffState | null>;
export async function executeUiAction(
  binding: ActionUiBinding, args: Record<string, unknown>,
  options: { document: Document; timeoutMs?: number; signal?: AbortSignal },
): Promise<{ ok: boolean; value?: string }>;
```

Runtime is a dependency-free IIFE that sets `window.Gap = { actions, call }`,
finds `[data-gap-action="..."]`, fills fields, clicks submit, waits for
`waitFor`/`result`, and returns the result text. Handoff tokens are
`v1.<base64url json>.<hmac>` using Web Crypto SHA-256; verify expiry and
constant-time compare. Tests use `happy-dom`.

## `gapmcp-evals`

```ts
export interface ToolChoice { tool: string | null; args?: unknown; reasoning?: string }
export interface Planner { choose(input: { prompt: string; tools: ToolDescriptor[]; system?: string }): Promise<ToolChoice> }
export class MockPlanner implements Planner { constructor(responses: ToolChoice[] | ((input) => ToolChoice | Promise<ToolChoice>)) }
export function httpPlanner(options: { endpoint: string; model: string; apiKey?: string; headers?: Record<string,string>; fetch?: typeof fetch }): Planner;
export interface EvalCase { name?: string; prompt: string; expectedTool: string; expectedArgs?: Record<string, unknown>; forbiddenTools?: string[] }
export interface EvalReport { total; passed; passRate; results; confusion; summary(): string; toJSON(): string }
export async function runEvals(options: { registry: ActionRegistry; cases: EvalCase[]; planner: Planner; scopes?: string[] }): Promise<EvalReport>;
export function lintRegistry(registry: ActionRegistry): { issues: RegistryIssue[]; ambiguous: Array<[string,string]>; score: number };
```

Argument scoring: subset match, deep equality for provided fields; report missing
and extra. Confusion matrix rows = expected, cols = chosen. `httpPlanner` uses
OpenAI-compatible `/chat/completions` with `tools`, parses the first tool call.
Lint adds token estimate and ambiguous sibling detection (Jaccard over
name/description tokens).

## `gapmcp-testing`

```ts
export function testPrincipal(overrides?: Partial<Principal>): Principal;
export function testContext(overrides?: Partial<ActionContext>): ActionContext;
export async function callAction(action: AnyAction, args: unknown, overrides?): Promise<unknown>;
export async function startTestServer(options: GapServerOptions): Promise<{ url; close(): Promise<void>; server: GapServer }>;
export async function callTool(options: { url: string; name: string; args?: unknown; token?: string; headers?: Record<string,string> }): Promise<{ isError: boolean; text: string; structured?: any }>;
export async function listTools(options: { url: string; token?: string }): Promise<ToolDescriptor[]>;
```

Uses the official MCP client against `startTestServer`.

## CLI (built separately)

`gap init`, `gap import openapi`, `gap lint`, `gap evals`, `gap inspect`,
`gap serve`, `gap dom`, `gap doctor`. The inspector serves a dependency-free
HTML UI and mounts the MCP endpoint at `/mcp`.

## Demo

`examples/demo` is an in-memory invoicing app with ~8 actions, policy, API-key
auth (`demo-key`), approvals, a task and a UI binding. `pnpm demo` starts it.
