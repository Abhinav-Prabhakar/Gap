# Gap

**Typed actions for agents.** One contract, compiled to an MCP tool, an OpenAPI
operation and a semantic UI binding — with delegated identity, policy,
approvals, audit and evals built in.

[![MIT License](https://img.shields.io/badge/license-MIT-c8f169)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-0a0c0f)](https://nodejs.org)
[![MCP](https://img.shields.io/badge/MCP-Streamable%20HTTP-0a0c0f)](https://modelcontextprotocol.io)
[![Status](https://img.shields.io/badge/status-alpha-e3b341)](#roadmap)

```ts
import { defineAction } from "gapmcp-core";
import { z } from "zod";

export const createInvoice = defineAction({
  name: "invoices.create",
  description:
    "Create a draft invoice for a customer. Computes the total from line items. Does not send it.",
  input: z.object({
    customerId: z.string().describe("Customer id, e.g. cus_8f2."),
    lineItems: z
      .array(z.object({ sku: z.string(), quantity: z.number().int().min(1) }))
      .min(1)
      .max(50)
      .describe("Line items to bill."),
  }),
  output: z.object({ id: z.string(), total: z.number() }),
  scopes: ["invoices:write"],
  risk: "medium",
  idempotent: true,
  execute: async (input, ctx) =>
    invoices.create({ ...input, actor: ctx.principal.id }),
});
```

```ts
// app/api/mcp/route.ts — any MCP client can now use it
import { createFetchHandler } from "gapmcp-server";
import { apiKeyAuth } from "gapmcp-auth";
import { createRegistry } from "gapmcp-core";

const handler = createFetchHandler({
  registry: createRegistry(createInvoice),
  auth: apiKeyAuth({
    keys: [{ key: process.env.GAP_TOKEN!, principal: { id: "agent", scopes: ["*"] } }],
  }),
});

export { handler as GET, handler as POST, handler as DELETE };
```

---

## The gap

Agents interact with software in one of two ways today:

1. **Computer-use** — screenshots and accessibility trees. Universal, but slow,
   brittle, expensive and blind to intent. A click is a guess about meaning.
2. **Bespoke integrations** — a hand-written tool for every app. Precise, but
   every integration reinvents auth, permissions, confirmation, audit and
   retries.

MCP standardised the transport between agents and tools, but not the layer above
it: a typed, permissioned, auditable **action** that application developers can
own. That layer is Gap.

```text
 application services / database
            │
     defineAction(...)
            │
      ActionRegistry ──────► MCP endpoint (Streamable HTTP / stdio) ──► agent
            │
            ├──────────────► OpenAPI operation
            ├──────────────► DOM manifest + browser runtime
            └──────────────► traces, audit, receipts, evals

     ctx = { principal, scopes, dryRun, approval, signal, tenantId }
```

The same action runs natively, falls back to semantic DOM when no action
exists, and hands off to a human when neither can finish.

## Why not just an MCP SDK?

| | Raw MCP SDK | OpenAPI → MCP generators | Gap |
| --- | --- | --- | --- |
| Typed tool contract | You design it | Generated, route-shaped | Yes, intent-shaped |
| Delegated user identity | You build it | Usually a service token | `jwtAuth` / token exchange |
| Scope-filtered discovery | You build it | Rarely | Built in |
| Human approval bound to args | You build it | No | HMAC grants, argument-bound |
| Blast-radius policy | You build it | No | Limits, confirm, dry-run |
| Idempotency, receipts, undo | You build it | No | Built in |
| UI fallback | Separate stack | No | Same contract → DOM |
| Tool-selection evals | You build it | No | Confusion matrix + linter |
| Audit trail | You build it | Partial | Every decision, hashed |

Generators solve *exposure*. Gap solves *trust*.

## Quickstart

```bash
npm install gapmcp-core gapmcp-server gapmcp-auth gapmcp-policy zod
npm install -D gapmcp-cli
```

Or install the standalone CLI:

```bash
brew install Abhinav-Prabhakar/tap/gap
# or: scoop install gap / winget install AbhinavPrabhakar.Gap
```

Define actions, mount the handler, connect a client:

```bash
npx gap init
npx gap inspect ./gap.actions.ts
```

The inspector gives you the tool surface, a live playground that goes through
the real MCP pipeline, the call log and an approval inbox:

```text
Gap Inspector
  UI   http://127.0.0.1:4400
  MCP  http://127.0.0.1:4400/mcp
```

Connect Claude Code, Claude Desktop, Cursor or any MCP client:

```json
{
  "mcpServers": {
    "my-app": {
      "command": "npx",
      "args": ["-y", "gapmcp-cli", "serve", "./gap.actions.ts", "--stdio"]
    }
  }
}
```

Full walkthrough: [`docs/quickstart.md`](./docs/quickstart.md).

## What you get

### A real action contract

`defineAction` gives you typed input/output (Zod 4 or JSON Schema), a
model-facing description, scopes, risk, idempotency, confirmation, examples, an
optional undo, a background-task hint and a UI binding. The registry compiles
all of it to MCP tool descriptors and validates it like a contract.

- **Compound skills** — `defineSkill` composes actions into one deterministic
  workflow, unioning scopes so composition cannot bypass policy.
- **Progressive disclosure** — `searchActions` and a `tools.search` meta-tool
  keep the visible tool count small as your surface grows.
- **Contract lint** — missing descriptions, risky actions without confirmation,
  ambiguous siblings and context-cost estimates.

### An MCP server with the boring-hard parts done

- Streamable HTTP (`POST`/`GET`/`DELETE /mcp`) and stdio.
- Stateful sessions or serverless-friendly stateless mode.
- Scope-filtered `tools/list`: an agent never sees a tool it cannot call.
- Structured output plus a text fallback; safe `GapError` payloads.
- Rate limiting, timeouts, abort signals and idempotent replay.
- Background tasks (`gap.tasks.get`, `gap.tasks.cancel`).
- Receipts and undo (`gap.receipts.get`, `gap.undo`).
- Signed human-handoff links (`gap.handoff`).
- CORS, DNS-rebinding protection, health and OAuth metadata endpoints.

### Delegated identity, not a god token

- `apiKeyAuth` for internal tools; constant-time comparison.
- `jwtAuth` as an OAuth 2.1 resource server: JWKS, issuer, audience, expiry.
- RFC 9728 protected-resource metadata and proper `WWW-Authenticate` challenges.
- RFC 8693 token exchange for on-behalf-of calls to downstream APIs.
- Per-action scopes, carried into `ctx.principal` and enforced inside your code.

### Approvals that cannot be swapped

High-risk actions park until a human approves. The grant is an HMAC-signed token
bound to the principal, the action and a canonical hash of the **exact**
arguments. Mutate any argument and the grant is void. Expired, tampered and
replayed tokens are rejected.

### Policy as code

Deny, confirm, cap money, cap arrays, force redaction, or run dry:

```json
{
  "version": 1,
  "default": "allow",
  "rules": [
    { "tools": ["orders.refund"], "maxAmount": 500, "amountPaths": ["amount"] },
    { "tools": ["invoices.send"], "confirm": true },
    { "tools": ["admin.*"], "deny": true },
    { "tools": ["customers.*"], "redact": ["email", "cards[].number"] }
  ]
}
```

### The fallback ladder

The same action compiles to a semantic DOM binding:

```ts
ui: {
  route: "/invoices/new",
  action: "invoices.create",
  fields: { customerId: "#customer", total: "#total" },
  submit: "#create-invoice",
  result: "#invoice-id",
}
```

```bash
gap dom ./actions.ts --runtime gap.dom.js
```

A browser agent can now call `Gap.call("invoices.create", args)` and let the
runtime fill, submit and read the result — no vision, no guessing. If it still
cannot finish, `gap.handoff` produces a signed, expiring deep link with the
draft state so a human can take over. See [`docs/fallback.md`](./docs/fallback.md).

### Agent readiness scan

```bash
gap score https://app.example.com
```

Checks an app for the signals an agent needs: an MCP endpoint, OpenAPI,
RFC 9728 metadata, an auth challenge, semantic DOM hooks, health and
`llms.txt`. It returns a score, a grade and one concrete recommendation per
missing signal — useful before you instrument a third-party app.

### Evals before users find out

```bash
gap evals ./evals.json --registry ./actions.ts --planner http
```

Subset argument scoring, forbidden tools, a confusion matrix per expected tool,
and a description linter that flags the sibling tools agents confuse. Tool
selection is a retrieval problem; measure it like one.

### Observability and audit

Every call produces a trace, an audit event and a receipt. Decisions
(`allowed`, `denied`, `error`, `approval_required`, `dry_run`), argument and
result hashes, duration, principal, tenant and approval id are recorded. Export
to OTel, JSONL, SIEM or your own sink. `ReplayRecorder` replays production calls
against a new build.

### Bring your existing surface

```bash
gap import openapi ./openapi.yaml --base-url https://api.example.com
```

Imports paths, parameters, bodies, output schemas and risk levels as draft
actions. Next.js route scanning is included. Generated actions are deliberately
marked for review: descriptions and risk are product decisions, not codegen
output.

## Packages

| Package | What it does |
| --- | --- |
| [`gapmcp-core`](./packages/core) | Action contract, registry, schema conversion, skills, search, errors |
| [`gapmcp-server`](./packages/server) | MCP transports and the full call pipeline |
| [`gapmcp-auth`](./packages/auth) | API keys, JWT/OAuth 2.1, approval tokens, token exchange, audit sinks |
| [`gapmcp-policy`](./packages/policy) | Limits, confirmation, dry-run, redaction |
| [`gapmcp-observability`](./packages/observability) | Tracers, call records, replay |
| [`gapmcp-importers`](./packages/importers) | OpenAPI and Next.js route importers |
| [`gapmcp-dom`](./packages/dom) | DOM manifest, browser runtime, signed handoff |
| [`gapmcp-evals`](./packages/evals) | Tool-selection evals and description linting |
| [`gapmcp-testing`](./packages/testing) | Test harness for actions and servers |
| [`gapmcp-cli`](./packages/cli) | `gap` CLI and inspector |
| [`gapmcp`](./packages/umbrella) | Umbrella package with subpath exports |

```ts
import { defineAction, createRegistry } from "gapmcp";
import { createFetchHandler } from "gapmcp/server";
import { apiKeyAuth } from "gapmcp/auth";
import { GapPolicy } from "gapmcp/policy";
```

## Demo

```bash
pnpm install
pnpm demo
```

An in-memory invoicing app with eight actions, two API keys (owner and
read-only), policy limits, an approval-gated send, a background export, receipts,
undo, audit and a UI binding. Try the read-only key to watch tools disappear
from discovery.

```bash
curl http://127.0.0.1:4400/info
pnpm gap inspect examples/demo/src/actions.ts --token demo-key
```

## Other languages

| Language | Status | Location |
| --- | --- | --- |
| TypeScript / Node | alpha, reference implementation | `packages/` |
| Python | alpha port (`pip install gapmcp`) | [`python/`](./python) |
| Go | alpha port (`go get github.com/Abhinav-Prabhakar/Gap/go`) | [`go/`](./go) |

The ports share the contract and the wire behaviour, not the code. They are
tested against the same fixtures and the same MCP client expectations.

## Security

The model is untrusted. Gap assumes prompt injection, confused-deputy attempts
and approval swapping will happen. Scopes, argument-bound approvals, policy
limits, dry-run, idempotency, redaction and hashed audit records are the
mitigations. Read [`SECURITY.md`](./SECURITY.md) before exposing an endpoint.

Production checklist:

- [ ] Auth configured; no anonymous endpoint.
- [ ] Scopes on every action; discovery filtered.
- [ ] `high`/`critical` actions require confirmation.
- [ ] Policy limits for money and rows.
- [ ] Shared stores for approvals, idempotency, rate limits and tasks.
- [ ] Audit persisted and monitored.
- [ ] Inspector not deployed.

See [`docs/deployment.md`](./docs/deployment.md).

## Documentation

- [Quickstart](./docs/quickstart.md)
- [Actions](./docs/actions.md)
- [Auth and identity](./docs/auth.md)
- [Policy](./docs/policy.md)
- [The fallback ladder](./docs/fallback.md)
- [Evals](./docs/evals.md)
- [CLI](./docs/cli.md)
- [Deployment](./docs/deployment.md)
- [Distribution](./docs/distribution.md)
- [Design notes](./DESIGN.md)

## Roadmap

- Hosted control plane: registry, OAuth broker, quotas, anomaly detection.
- Multi-app gateway: one endpoint and one consent screen for many apps.
- MCP UI resources (`ui://`) so approvals and receipts render as components.
- Record-a-human-once: turn an instrumented flow into an action stub.
- More language ports (Rust, Java/Kotlin) and a conformance suite.

## Contributing

Issues and PRs are welcome. There is intentionally no CI: lint, typecheck, tests
and builds run locally before release.

```bash
pnpm install
pnpm test
pnpm typecheck
pnpm build
```

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). By participating you agree to the
[Code of Conduct](./CODE_OF_CONDUCT.md).

## License

MIT © [Abhinav Prabhakar](https://github.com/Abhinav-Prabhakar)
