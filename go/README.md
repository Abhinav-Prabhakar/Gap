# Gap for Go

[Gap](../../README.md) is a typed action layer for agents: define an action once,
then serve it as an MCP tool through one authentication, scope, policy, approval,
rate-limit, validation, audit and receipt pipeline.

This package is the Go implementation of the Gap core and server. It is a
standalone library with no dependency on the TypeScript packages.

```go
import "github.com/Abhinav-Prabhakar/Gap/go"
```

The package name is `gap`.

## Quick start

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Abhinav-Prabhakar/Gap/go"
)

type CreateInvoiceInput struct {
	Customer string  `json:"customer" jsonschema:"description=Customer id,required"`
	Total    float64 `json:"total" jsonschema:"description=Amount in cents,minimum=0,required"`
}

type CreateInvoiceOutput struct {
	ID string `json:"id" jsonschema:"description=Created invoice id,required"`
}

func main() {
	createInvoice := gap.Define[CreateInvoiceInput, CreateInvoiceOutput](gap.Action{
		Name:        "invoices.create",
		Description: "Create an invoice for a customer. This writes to the billing system.",
		Scopes:      []string{"invoices:write"},
		Risk:        gap.RiskMedium,
		Confirm:     true,
		Tags:        []string{"billing"},
	}, func(ctx context.Context, input CreateInvoiceInput, actx *gap.Context) (CreateInvoiceOutput, error) {
		// actx carries the authenticated principal, scopes, tenant, trace id,
		// approval grant and logger. Never read ambient credentials here.
		return CreateInvoiceOutput{ID: fmt.Sprintf("inv_%s", input.Customer)}, nil
	})

	registry := gap.NewRegistry(createInvoice)

	audit, err := gap.NewJSONLAuditLog("audit.jsonl")
	if err != nil {
		log.Fatal(err)
	}
	defer audit.Close()

	server, err := gap.NewServer(gap.ServerOptions{
		Registry: registry,
		Name:     "billing-gap",
		Auth: gap.NewAPIKeyAuth(gap.APIKeyAuthOptions{
			Keys: []gap.APIKeyRecord{{
				Key: os.Getenv("GAP_API_KEY"),
				Principal: gap.Principal{
					ID:     "usr_1",
					Type:   gap.PrincipalUser,
					Scopes: []string{"invoices:write"},
				},
			}},
		}),
		BaseURL: "https://gap.example.com",
		Audit:   audit,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close(context.Background())

	log.Fatal(http.ListenAndServe(":8080", server))
}
```

The HTTP server exposes:

| Route | Purpose |
| --- | --- |
| `POST /mcp` | MCP Streamable HTTP, stateless, JSON responses |
| `GET /health` | Liveness, package name/version, uptime, action count |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 protected-resource metadata |

`/mcp` accepts only POST. GET and DELETE return `405` with `Allow: POST`
(the stateless transport has no server-initiated stream or session to delete).

## Defining actions

### Typed actions

`Define[I, O]` derives draft 2020-12 schemas from Go types with
`github.com/invopop/jsonschema`:

- Use `json` tags for property names.
- Use `jsonschema` tags for descriptions, required fields and constraints, for
  example `jsonschema:"description=Customer id,required"` or
  `jsonschema:"description=Amount in cents,minimum=0"`.
- Inputs are validated before the handler runs; the handler receives the typed
  value.
- Outputs are validated when an output schema exists.
- When `O` is `any`, an empty struct, or otherwise schema-less, no output schema
  is advertised.
- Object-shaped output schemas are advertised through MCP `outputSchema`.
  Non-object schemas are kept in `_meta["gap/outputSchema"]`.

### Untyped actions

`DefineAction` is the untyped form. It normalizes the name (trimming and
replacing whitespace with `.`), defaults `Risk` to `low`, defaults `Version` to
`1`, and installs an empty object schema when none is supplied.

```go
action := gap.DefineAction(gap.Action{
	Name:        "reports.read",
	Description: "Read a report without changing server state.",
	Tags:        []string{"read-only"},
	InputSchema: map[string]any{
		"type": "object",
		"properties": map[string]any{
			"id": map[string]any{"type": "string", "description": "Report id."},
		},
		"required":             []string{"id"},
		"additionalProperties": false,
	},
	Execute: func(ctx context.Context, input any, actx *gap.Context) (any, error) {
		id := input.(map[string]any)["id"].(string)
		return map[string]any{"id": id}, nil
	},
})
```

An action may also declare:

- `Confirm` / `ConfirmFunc`: require human approval.
- `Undo`: a best-effort inverse used by `gap.undo`.
- `Task`: run in the background and return a task id.
- `UI`: a route/action binding used by `gap.handoff`.
- `Timeout`: a per-action execution budget.
- `Annotations`, `Meta`, `Examples`, `Deprecated`, `DeprecatedMessage`.
- `Idempotent`: cache successful results for the same principal and arguments.

`Registry` is concurrency-safe. `NewRegistry` panics on invalid actions;
`Add` returns an error and rolls back the whole call if any action is invalid.
`Registry.Validate()` performs CI-friendly contract checks (descriptions,
schema compilation, undescribed fields, risky operations without confirmation,
poor scope names, invalid timeouts).

Inspect descriptors with `registry.ToToolDescriptors` or
`server.ListTools(scopes)`.

## Server pipeline

Every action call passes through the same stages, in order:

1. **Lookup** — unknown tools become `NOT_FOUND`.
2. **Scopes** — the principal must hold every scope the action requires.
3. **Policy** — `allow`, `deny` or `confirm`; deny wins.
4. **Rate limit** — token bucket keyed by principal and action.
5. **Input validation** — JSON Schema; issues are returned as
   `INVALID_INPUT`.
6. **Idempotency** — explicit keys and automatically for idempotent actions.
7. **Approval** — policy confirmation, `Confirm`/`ConfirmFunc`, an approved
   store record, or a signed `gap/approval` token.
8. **Execution** — with a timeout and panic recovery.
9. **Output validation** — against `OutputSchema`, when present.
10. **Redaction** — policy and server redaction paths.
11. **Receipt and call record** — hashes, duration, approval id, trace id.
12. **Audit** — hashed arguments/results, decision, error summary, metadata.

The action never sees a raw token: `Context` carries only the authenticated
principal, scopes, tenant, approval grant and trace id.

### Error contract

Tool failures are MCP tool results with `isError: true` and a structured
payload:

```json
{
  "gapError": {
    "name": "GapError",
    "code": "INVALID_INPUT",
    "message": "Invalid input for \"invoices.create\".",
    "status": 400,
    "retryable": false,
    "details": { "issues": [{ "path": "total", "message": "..." }] }
  }
}
```

The text content always carries a human-readable message. Internal errors hide
their cause and details; `gap.NewError`, `gap.Errorf` and `gap.AsError` are
available for application errors, and `Normalize` converts anything else safely.

## Authentication

### API keys

```go
auth := gap.NewAPIKeyAuth(gap.APIKeyAuthOptions{
	Keys: []gap.APIKeyRecord{{
		Key: "secret",
		Principal: gap.Principal{
			ID:       "usr_1",
			Type:     gap.PrincipalUser,
			TenantID: "ten_1",
			Scopes:   []string{"invoices:write"},
		},
	}},
})
```

Keys are compared by SHA-256 digest in constant time. Both `X-API-Key` and
`Authorization: Bearer …` are accepted by default; restrict with `Header:
"x-api-key"` or `Header: "authorization"`. `Resolve` supports dynamic lookup.

### JWTs

```go
auth, err := gap.NewJWTAuth(gap.JWTAuthOptions{
	Issuer:   "https://auth.example.com",
	Audience: []string{"gap"},
	JWKSURI:  "https://auth.example.com/.well-known/jwks.json",
})
```

- RS256/384/512, PS256/384/512, ES256/384/512 and EdDSA are accepted.
- `exp` is required; `nbf` and `iat` respect `ClockTolerance`.
- Standard claims map `sub`, `scope`/`scp`, `tenant_id`, `email`, `name` and
  `type`. Use `MapClaims` for custom identities, or `Keyfunc` to replace JWKS
  resolution.
- `alg: none` and unknown key ids are rejected.

`ComposeAuth` tries providers in order. `APIKeyAuth`, `JWTAuth` and
`ComposeAuth` implement `AuthChallenger` and produce `WWW-Authenticate: Bearer`
headers. Both implement `ProtectedResourceMetadata`; the server also builds a
metadata document from the registry when the provider does not supply one.

When no provider is configured, requests run as the anonymous principal with
`["*"]` scopes. A configured provider returning no credentials rejects the
request. Provider errors fail closed.

## Policy

```go
policy, err := gap.NewGapPolicyJSON(`{
  "version": 1,
  "default": "allow",
  "rules": [
    {
      "tools": ["invoices.*"],
      "maxAmount": 100000,
      "reason": "Invoices above 1,000 need review"
    },
    {
      "tools": ["invoices.delete"],
      "deny": true,
      "reason": "Deletes are disabled"
    },
    {
      "tools": ["reports.*"],
      "confirm": true
    }
  ],
  "redact": ["customer.ssn"]
}`)
```

Rules are evaluated in order. A matching deny or limit violation denies
immediately. `maxAmount` inspects numeric fields recursively using
`amountPaths` (default: `amount`, `total`, `value`, `price`, `cost`).
`maxArrayLength` checks every array, or only `arrayPaths`. `dryRun` sets
`Context.DryRun` and returns arguments without executing. `redact` paths use
dot/bracket syntax (`customer.ssn`, `items[].card`) and apply to both dry-run
arguments and results.

Implement `PolicyEngine` directly for dynamic policies. A policy panic or an
invalid decision is treated as `POLICY_DENIED`.

## Approvals

Approval is required when any of these is true:

- A policy rule or document glob matches with `confirm`.
- The action has `Confirm: true`.
- `ConfirmFunc` returns true.
- An approval token is supplied but does not cover the call.

The first call returns a successful result with:

```json
{
  "status": "approval_required",
  "action": "invoices.create",
  "approvalId": "apr_…",
  "approveUrl": "https://gap.example.com/approvals/apr_…",
  "expiresAt": "2026-01-01T00:00:00Z",
  "argsHash": "…",
  "retry": true
}
```

An operator approves or denies out of band:

```go
_, err = server.ApprovalStore().Approve(approvalID, gap.ResolveApprovalOptions{
	Actor: "ops@example.com",
})
// or Deny with a reason.
```

The retried call with the same arguments consumes the approval and executes.
Denied approvals return `APPROVAL_REQUIRED` with the reason. Approvals are bound
to the principal, action and argument hash, and expire after `ApprovalTTL`
(default 5 minutes). `MemoryApprovalStore` is concurrency-safe and single
process; implement `ApprovalStore` for shared storage.

For stateless approval tokens, configure `Approvals`:

```go
gate, _ := gap.NewHMACApprovalGate(gap.HmacApprovalGateOptions{Secret: secret})
server, _ := gap.NewServer(gap.ServerOptions{Registry: registry, Approvals: gate})
```

Issue a token after a human approves, and pass it in the MCP call's `_meta`:

```json
{
  "gap/approval": "v1.<payload>.<signature>"
}
```

Tokens are HMAC-SHA256 over the action, principal and exact argument hash, and
expire. `approvalToken` is accepted as an alias key.

The server returns approval links but does not itself serve `/approvals/…`;
wire that route to your own approval UI.

## Receipts, undo, tasks, handoff and search

### Receipts

Successful calls put a receipt reference on the MCP result:

```json
{
  "_meta": {
    "gap/receipt": { "id": "rcpt_…", "action": "invoices.create", "undoable": false },
    "gap/traceId": "trace_…"
  }
}
```

`gap.receipts.get` (`{ "receiptId": "…" }`) returns the receipt, arguments and
redacted result. Receipts are scoped to the principal that created them. The
call store is a bounded ring buffer (`CallStoreLimit`, default 500); inject
your own persistence for production.

### Undo

Actions with `Undo` are undoable. `gap.undo` (`{ "receiptId": "…" }`) runs the
inverse with the original input and unredacted output, marks the original call
undone, and returns a new receipt with `undoOf`. Repeated undo returns
`CONFLICT`.

### Tasks

Set `Task: true` to run in the background. The initial result is:

```json
{ "status": "working", "taskId": "task_…", "action": "reports.generate" }
```

`gap.tasks.get` returns the task status, result and receipt; `gap.tasks.cancel`
triggers the task context immediately. Tasks are in-memory and process-local.
`EnableTasks: false` runs task actions synchronously and hides the task tools.

### Handoff

Configure `HandoffSecret` and give an action a `UI` binding:

```go
gap.Action{
	Name: "invoices.create",
	UI:   &gap.ActionUI{Route: "/invoices/new"},
	// ...
}
```

`gap.handoff` validates the action's arguments and returns:

```json
{
  "action": "invoices.create",
  "url": "https://app.example.com/invoices/new?gap_state=v1.…",
  "expiresAt": 1767225600000
}
```

The signed token is also returned in `_meta.token`. Verify it in the UI with
`HandoffStateFromURL(url, secret, gap.HandoffVerifyOptions{...})` or
`VerifyHandoffToken`. The state binds action, arguments, principal, tenant and
expiry. Links expire after `HandoffTTL` (default 10 minutes). `gap.handoff` is
only advertised when a secret is configured and at least one visible action has
a UI binding.

### Search

When a principal can see more than `SearchThreshold` actions (default 12) the
server also advertises `gap.search`. It filters by case-insensitive query
terms, namespace prefix, required tags and a limit (1–50, default 10), returning
matching tool definitions with input schemas. Set `SearchThreshold: -1` to
disable it.

## Auditing and redaction

Audit events include the principal, tenant, scopes, decision (`allowed`,
`denied`, `error`, `approval_required`, `dry_run`), argument and result
hashes, duration, approval id, trace id and a safe error summary. Raw arguments
and results are never written.

```go
audit := gap.NewMemoryAuditLog()                      // tests/inspectors
file, _ := gap.NewJSONLAuditLog("audit.jsonl")       // append-only, 0600
server, _ := gap.NewServer(gap.ServerOptions{
	Registry:   registry,
	Audit:      audit,
	AuditSinks: []gap.AuditSink{file},               // fan-out
})
```

Sink failures are logged and never fail the call. `OnCall` observes every
stored call after redaction, for metrics or custom persistence. Returned
results are redacted according to policy `redact` paths plus
`ServerOptions.Redact`; the raw result stays in the server-side call record for
undo and operator inspection.

## Stdio

```go
server, err := gap.NewServer(gap.ServerOptions{Registry: registry})
if err != nil {
	log.Fatal(err)
}
if err := server.ServeStdio(context.Background()); err != nil {
	log.Fatal(err)
}
```

`gap.ServeStdio(ctx, server)` is an equivalent package-level helper. Stdio runs
as the anonymous principal with `["*"]` scopes; use HTTP when authentication is
required.

## Configuration reference

| Option | Default | Purpose |
| --- | --- | --- |
| `Registry` | required | Action catalog |
| `Name`, `Version`, `Instructions` | `gap`, `Version`, empty | MCP implementation info |
| `Auth` | nil | `AuthProvider`; nil allows anonymous |
| `AllowAnonymous` | `Auth == nil` | Allow missing credentials |
| `Policy` | allow all | `PolicyEngine` |
| `Audit`, `AuditSinks` | none | Audit sinks |
| `Logger` | no-op | Server warnings |
| `Approvals` | nil | `ApprovalGate` for signed tokens |
| `ApprovalStore` | in-memory | Pending approval storage |
| `RateLimiter`, `RateLimit` | unlimited | Token bucket (`Limit`, `Window`, `Now`) |
| `Idempotency` | in-memory | Result cache |
| `BaseURL` | derived from request | Public origin for links |
| `HandoffSecret` | empty | Enables `gap.handoff` |
| `EnableTasks` | true | Background task actions |
| `CallStoreLimit` | 500 | Retained receipts |
| `Timeout` | 30s | Default execution budget |
| `ApprovalTTL` | 5m | Pending approval lifetime |
| `HandoffTTL` | 10m | Handoff link lifetime |
| `Redact` | none | Extra result redaction paths |
| `SearchThreshold` | 12 | Enable `gap.search` above this; negative disables |
| `OnCall` | nil | Post-redaction call observer |

## Testing actions

`gap/testing.go` mirrors the TypeScript testing helpers:

```go
func TestCreateInvoice(t *testing.T) {
	out, err := gap.CallAction(createInvoice, map[string]any{
		"customer": "cus_1",
		"total":    1200,
	})
	if err != nil {
		t.Fatal(err)
	}
	// out is the validated JSON value of CreateInvoiceOutput.
}
```

`CallAction` validates input, executes the action, and validates output. It
bypasses auth, policy, rate limits, approvals, receipts and audit, so use it for
unit tests. Pass options to control the context:

```go
out, err := gap.CallAction(action, input, gap.TestContextOptions{
	Principal: gap.Ptr(gap.TestPrincipal(gap.TestPrincipalOptions{
		ID:       "usr_1",
		TenantID: "ten_1",
		Scopes:   []string{"invoices:write"},
	})),
	DryRun: true,
	Services: map[string]any{"db": db},
})
```

For end-to-end tests, use `httptest.NewServer(server)` and connect the official
SDK client with `mcp.StreamableClientTransport` and
`DisableStandaloneSSE: true`. The package's own tests do exactly this.

## Architecture and statelessness

`Server` owns process-wide state: the registry, call store, approval store,
task manager, rate limiter, idempotency cache and audit sinks. It implements
`http.Handler` and routes the three HTTP endpoints.

The MCP layer is intentionally stateless. For each `POST /mcp`, the server:

1. authenticates the request,
2. puts the `AuthResult` in the request context,
3. asks the SDK's Streamable HTTP handler for a fresh per-request
   `*mcp.Server`,
4. registers only the tools visible to that principal, and
5. disposes the protocol server when the response is written.

That means tool listings, schemas and descriptions are filtered per principal,
and no session state is shared between requests. Horizontal scaling only needs
shared implementations of the stores if you need receipts, approvals, tasks or
idempotency to survive a process restart; the protocol layer itself has no
sticky-session requirement.

The SDK's tool registry only knows the visible tools. Calls to hidden or unknown
tool names are intercepted by a receiving middleware and sent through Gap's
pipeline, so they become `isError` tool results with a `gapError` payload rather
than JSON-RPC errors. The TypeScript server behaves the same way by handling
`tools/call` itself.

Built-in tools are available as follows:

| Tool | Availability |
| --- | --- |
| `gap.receipts.get` | Always |
| `gap.tasks.get`, `gap.tasks.cancel` | `EnableTasks` |
| `gap.undo` | At least one visible action has `Undo` |
| `gap.handoff` | `HandoffSecret` set and a visible action has `UI` |
| `gap.search` | Visible actions exceed `SearchThreshold` |

Action names `gap.tasks.get`, `gap.tasks.cancel`, `gap.receipts.get`,
`gap.undo`, `gap.handoff` and `gap.search` are reserved; `NewServer` refuses a
registry that uses them.

## Concurrency and limits

- `Registry`, stores, the limiter and the task manager are safe for concurrent
  use. Actions may be invoked concurrently; do not mutate an action after it is
  registered.
- `MemoryApprovalStore`, `MemoryIdempotencyStore`, `CallStore` and
  `TaskManager` are process-local. Replace them for multi-instance deployments.
- Default limits are deliberately conservative: 4 MiB request bodies, 500
  retained calls, 30-second execution, 5-minute approvals, 10-minute handoff
  links.
- Background tasks are cancelled by `Server.Close`, which waits for the supplied
  context.
- In-flight idempotent calls are coalesced: concurrent callers with the same key
  wait for the first result instead of duplicating side effects.

## Dependencies

- `github.com/modelcontextprotocol/go-sdk v1.8.0` — MCP server and client.
- `github.com/santhosh-tekuri/jsonschema/v6` — draft 2020-12 validation.
- `github.com/invopop/jsonschema` — Go type to schema reflection.
- `github.com/golang-jwt/jwt/v5` — JWT verification.

Go 1.25 or newer is required; the MCP Go SDK sets that floor. The module's `go`
directive is the authoritative minimum.

## Development

```sh
go mod tidy
go vet ./...
go test -race ./...
go build ./...
```

The test suite includes schema/action tests, registry contract checks, policy
tables, API key and JWT authentication, HMAC approvals, rate limiting,
idempotency, audit sinks, receipts/undo, tasks, handoff, search, error payload
shapes, output validation and redaction, and an end-to-end SDK client over
`httptest`.
