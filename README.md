# Gap

**Typed actions for agents.** One action contract, compiled to an MCP tool, an
OpenAPI operation and a semantic UI binding — with delegated identity, policy,
approvals, audit and evals built in.

```ts
import { defineAction } from "gapmcp-core";
import { z } from "zod";

export const createInvoice = defineAction({
  name: "invoices.create",
  description: "Create a draft invoice for a customer. Does not send it.",
  input: z.object({
    customerId: z.string().describe("Customer id, e.g. cus_8f2."),
    total: z.number().positive().describe("Invoice total in USD."),
  }),
  risk: "medium",
  scopes: ["invoices:write"],
  execute: async ({ customerId, total }, ctx) =>
    db.invoices.create({ customerId, total, actor: ctx.principal.id }),
});
```

Then mount the MCP endpoint:

```ts
import { createFetchHandler } from "gapmcp-server";
import { registry } from "./actions";

export const GET = createFetchHandler({ registry });
export const POST = createFetchHandler({ registry });
```

> **Status:** early. The TypeScript implementation, Python and Go ports,
> inspector and CLI are being built in the open. Star the repo to follow along.

## Why

Computer-use is the universal fallback, not the interface. Screenshots and
accessibility trees are slow, brittle and blind to intent. Gap lets application
developers expose *semantic actions* instead: typed, permissioned, auditable,
and usable by any MCP client. When no action exists, the same contract compiles
to DOM bindings so a browser agent can still act on intent rather than pixels.

## Packages

| Package | What it does |
| --- | --- |
| `gapmcp-core` | Action contract, registry, schema conversion, errors |
| `gapmcp-server` | MCP over Streamable HTTP/stdio, approvals, tasks, receipts |
| `gapmcp-auth` | API keys, JWT/OAuth 2.1, approval tokens, audit sinks |
| `gapmcp-policy` | Limits, confirmations, dry-run, redaction |
| `gapmcp-observability` | Tracing, replay, audit |
| `gapmcp-importers` | OpenAPI and Next.js route importers |
| `gapmcp-dom` | Semantic DOM bindings and signed handoff links |
| `gapmcp-evals` | Tool-selection evals and description linting |
| `gapmcp-testing` | Test harness |
| `gapmcp-cli` | `gap` CLI and inspector |

MIT licensed.
