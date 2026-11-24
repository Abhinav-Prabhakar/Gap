# gapmcp

Typed actions, policy, auth and a [Model Context Protocol](https://modelcontextprotocol.io)
server for agents — the Python implementation of the Gap action contract.

Define an action once. Gap turns it into an MCP tool, enforces scopes, policy,
approvals, rate limits and validation, runs it with a timeout, redacts the
result, writes an audit event and stores a receipt.

```bash
# PyPI publication is pending. Install the wheel from the release meanwhile:
pip install https://github.com/Abhinav-Prabhakar/Gap/releases/download/v0.1.0/gapmcp-0.1.0-py3-none-any.whl
```

Python 3.10+. The package name on PyPI will be `gapmcp`.

## Quick start

```python
from pydantic import BaseModel, Field
from gapmcp import create_registry, create_server, define_action

class CreateInvoiceInput(BaseModel):
    customer_id: str = Field(description="Customer to invoice.")
    amount: float = Field(gt=0, description="Invoice total in USD.")

@define_action(
    name="invoices.create",
    description="Create a draft invoice for a customer and return its id.",
    input=CreateInvoiceInput,
    scopes=["invoices:write"],
    risk="medium",
    idempotent=True,
    tags=["invoices"],
)
async def create_invoice(input: CreateInvoiceInput, ctx):
    return {"id": "inv_123", "amount": input.amount, "customerId": input.customer_id}

registry = create_registry(create_invoice)
server = create_server(registry)
```

Serve over stdio:

```python
import asyncio
asyncio.run(server.run_stdio())
```

Or mount Streamable HTTP in an ASGI app:

```bash
uvicorn app:app
```

```python
app = server.streamable_http_app()  # /mcp, /health, /.well-known/oauth-protected-resource
```

## Defining actions

`define_action` works as a decorator or a direct call. All three forms are
equivalent:

```python
# 1. Decorator with options
@define_action(name="invoices.get", description="Fetch one invoice by id.")
async def get_invoice(input, ctx): ...

# 2. Direct call with the function
async def get_invoice(input, ctx): ...
get_invoice = define_action(get_invoice, name="invoices.get", description="...")

# 3. Reusable template, then decoration
async def draft(input, ctx): ...
template = define_action(draft, name="invoices.get", description="Fetch one invoice by id.")
get_invoice = define_action(template)(get_invoice)
```

Calling `define_action` with options but no function returns a decorator, so
`define_action(name=..., description=...)` can also be used directly as a
decorator. Passing `execute=` builds the action immediately:
`define_action(name=..., description=..., execute=fn)`.

Actions are not called directly; pass them to `ActionRegistry` / a server, or
use `run_action` / `gapmcp.testing.call_action`. Action fields mirror the
TypeScript contract: `name`, `description`, `input`, `output`, `scopes`,
`risk`, `idempotent`, `confirm`, `tags`, `examples`, `annotations`, `ui`,
`undo`, `meta`, `timeout_ms`, `task`, `deprecated`, `version` and `title`.
`input` and `output` accept a pydantic model class or a plain JSON Schema dict.

Handlers receive `(input, ctx)` where `ctx` carries the principal, scopes,
tenant, dry-run flag, approval grant, abort signal, trace id, logger, services
and the framework request. Inputs are validated before the handler runs;
outputs are validated when an `output` schema is declared.

### Skills

A skill composes actions and inherits their scopes:

```python
from gapmcp import define_skill, run_action

create_ticket = define_skill(
    uses=[create_invoice],
    name="support.escalate",
    description="Create an invoice and open an escalation ticket together.",
    scopes=["tickets:write"],
)
async def escalate(input, ctx, run):
    invoice = await run(create_invoice, input)
    return {"invoice": invoice}
```

`run(child, args)` validates the child's input and reuses the same context, so
composition cannot bypass the server pipeline.

## Registry and tool descriptors

```python
from gapmcp import ActionRegistry, create_registry

registry = ActionRegistry([create_invoice])
registry.get("invoices.create")
registry.visible_to(["invoices:read"])          # scope-filtered discovery
registry.to_tool_descriptors(scopes=["*"])
issues = registry.validate()                     # CI-friendly contract checks
```

`validate()` catches missing/short descriptions, non-object inputs,
undescribed fields, scope format, high-risk actions without confirmation and
incomplete UI bindings. Errors should fail a build; warnings are advice.

## Policy

```python
from gapmcp import GapPolicy, define_policy

policy = GapPolicy(define_policy({
    "version": 1,
    "default": "allow",
    "rules": [
        {"tools": ["invoices.*"], "maxAmount": 10_000, "redact": ["customer.email"]},
        {"tools": ["invoices.delete", "invoices.refund"], "deny": True, "reason": "Finance review required."},
        {"tools": ["invoices.send"], "confirm": True, "dryRun": False},
    ],
}))

server = create_server(registry, policy=policy)
```

Rules match a tool name exactly or with a `prefix.*` glob. The first matching
deny wins, any matching confirm asks for approval, otherwise the call is
allowed. `maxAmount` scans the default amount keys (`amount`, `total`, `value`,
`price`, `cost`) recursively, or explicit `amountPaths`. `maxArrayLength`
applies to any array, or explicit `arrayPaths`. Limit violations return
`POLICY_DENIED` with code `LIMIT_EXCEEDED`. `redact` paths merge across matching
rules and apply to both the returned result and receipt. `dryRun` is exposed to
handlers as `ctx.dry_run`. Rules may also set `scopes` to apply only to
principals holding them.

## Auth

API keys accept `Authorization: Bearer <key>` or `X-API-Key`, compared in
constant time:

```python
from gapmcp import ApiKeyAuth, ApiKeyRecord, Principal

auth = ApiKeyAuth([
    ApiKeyRecord(
        key="replace-me",
        principal=Principal(id="svc_billing", type="service", scopes=["invoices:write"]),
    ),
])
```

JWTs verify signature, issuer, audience, expiry and required `sub`/`exp` claims
with PyJWT, using a local JWKS or a remote `jwks_uri`:

```python
from gapmcp import JwtAuth

auth = JwtAuth(
    issuer="https://auth.example.com",
    audience="https://billing.example.com/mcp",
    jwks_uri="https://auth.example.com/.well-known/jwks.json",
)
```

`compose_auth(...)` tries providers in order. When `base_url` is configured,
the server exposes RFC 9728 protected-resource metadata and returns a
`WWW-Authenticate` challenge on 401. If an auth provider is configured for
stdio or in-process clients, pass `stdio_principal` explicitly; there is no
silent anonymous fallback in that configuration.

## Approvals

Mark an action `confirm=True`, or require confirmation from policy. The first
call returns `{status: "approval_required", approvalId, retry: true}` and stores
a pending record bound to the principal, action and argument hash. After
approval, the same call executes once:

```python
pending = server.pending_approvals()
server.approve(pending[0]["approvalId"], approved_by="alice@example.com")
```

For stateless deployments, configure an HMAC gate and pass the token to the
call as `_meta["gap/approval"]`:

```python
from gapmcp import HmacApprovalGate

gate = HmacApprovalGate("a-long-random-secret", ttl_ms=10 * 60 * 1000)
token, grant = gate.issue(
    action="invoices.delete",
    args={"id": "inv_123"},
    principal_id="usr_123",
)
server = create_server(registry, approvals=gate)
```

Tokens are `v1.<base64url payload>.<base64url HMAC-SHA256>` and bind the exact
canonical argument hash, principal and expiry. Tampered, expired or replayed
against different arguments tokens are rejected.

`allow_elicitation=True` lets the server ask through MCP elicitation when the
client supports it before falling back to a pending approval.

## Pipeline

Every call runs:

1. authentication
2. scope check
3. policy decision
4. rate limit (per principal + tool)
5. input validation
6. approval (store, HMAC token or elicitation)
7. execute with timeout and abort signal
8. output validation
9. redaction
10. audit event
11. receipt

Errors become MCP tool errors with `isError: true` and
`structuredContent.gapError` containing a stable code, message, status,
retryable flag and safe details:

```json
{
  "gapError": {
    "code": "INVALID_INPUT",
    "message": "Invalid input.",
    "status": 400,
    "retryable": false,
    "details": {"issues": [{"path": "amount", "message": "..."}]}
  }
}
```

## Meta tools

The server adds these when relevant:

| Tool | When | Purpose |
| --- | --- | --- |
| `gap.search` | more than 12 actions | Rank actions by intent with scope filtering |
| `gap.tasks.get` / `gap.tasks.cancel` | any `task=True` action | Poll or cancel background work |
| `gap.receipts.get` | always | Fetch a redacted call receipt |
| `gap.undo` | any action with `undo` | Run the action's best-effort inverse |
| `gap.handoff` | `handoff_secret` and a UI binding | Signed, expiring human handoff URL |

Names beginning with `gap.` are reserved. Actions with `task=True` return
`{taskId, status: "working"}` immediately.

## Rate limits and idempotency

```python
from gapmcp import RateLimit, create_server

server = create_server(
    registry,
    rate_limit=RateLimit(limit=60, window_ms=60_000),
)
```

Idempotent actions replay their first result for the TTL, and concurrent calls
with the same key wait for one execution. Send an explicit key as
`_meta["idempotencyKey"]`. Stores are in-process; use a shared implementation
for multiple replicas.

## Audit

```python
from gapmcp import JsonlAuditLog, MemoryAuditLog

audit = JsonlAuditLog("./audit.jsonl")
server = create_server(registry, audit=audit)
```

Events record the decision, principal, tenant, hashed arguments and result,
duration, approval id, trace id and safe error code. Raw arguments, results and
secrets are never logged. `MemoryAuditLog` is the default and is convenient in
tests.

## Testing

```python
from gapmcp.testing import call_action, call_tool, test_context, test_principal

result = await call_action(create_invoice, {"customer_id": "cus_1", "amount": 42})
response = await call_tool(server, "invoices.create", {"customer_id": "cus_1", "amount": 42})
```

`GapServer.call_tool` bypasses the transport but not the pipeline, so policy,
validation, approvals and audit still apply. For a real MCP round trip, connect
the official SDK client in-process:

```python
from mcp import Client

async with Client(server.server) as client:
    tools = await client.list_tools()
    result = await client.call_tool("invoices.create", {"customer_id": "cus_1", "amount": 42})
```

## Differences from the TypeScript packages

- Pydantic models replace Zod; plain JSON Schema works in both.
- `define_action` is a Python decorator/direct-call API rather than a single
  options object.
- Module-level helpers use `snake_case`; wire formats (tool annotations, audit
  events, errors, receipts and approval tokens) keep the TypeScript camelCase
  names.
- Importer, DOM runtime, eval, CLI and observability packages are not ported
  here.
- Rate-limit, idempotency, approval and receipt stores are in-process; the
  TypeScript server also only ships in-memory defaults.

## Security

- Never log tokens, raw arguments or results; audit hashes values instead.
- Treat tool arguments as untrusted and keep scopes narrow.
- Serve Streamable HTTP with authentication in production. The default
  anonymous `["*"]` principal is for local development and stdio only.
- DNS-rebinding protection defaults to localhost; set `allowed_hosts` and
  `allowed_origins` when serving a public hostname.

## License

MIT
