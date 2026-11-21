# Quickstart

Gap turns application functions into typed agent actions. You keep your code,
database and auth; Gap adds the MCP surface and the safety rail.

## 1. Install

```bash
npm install gapmcp-core gapmcp-server gapmcp-auth gapmcp-policy zod
```

For the local inspector and CLI:

```bash
npm install -D gapmcp-cli
```

## 2. Define an action

```ts
// actions.ts
import { defineAction } from "gapmcp-core";
import { z } from "zod";

export const createInvoice = defineAction({
  name: "invoices.create",
  description:
    "Create a draft invoice for a customer. Computes the total from line items. Does not send it.",
  input: z.object({
    customerId: z.string().describe("Customer id, e.g. cus_8f2."),
    lineItems: z
      .array(
        z.object({
          sku: z.string().describe("SKU or service code."),
          quantity: z.number().int().min(1).describe("Units to bill."),
        }),
      )
      .min(1)
      .max(50)
      .describe("Line items to bill."),
  }),
  output: z.object({
    id: z.string().describe("New invoice id."),
    total: z.number().describe("Invoice total in USD."),
  }),
  scopes: ["invoices:write"],
  risk: "medium",
  idempotent: true,
  execute: async ({ customerId, lineItems }, ctx) => {
    // ctx.principal is the *delegated user*, not a service account.
    return invoices.create({ customerId, lineItems, actor: ctx.principal.id });
  },
});

export const listInvoices = defineAction({
  name: "invoices.list",
  description: "List invoices for the current tenant. Read-only and safe to repeat.",
  input: z.object({ status: z.enum(["draft", "sent", "paid"]).optional() }),
  output: z.object({ invoices: z.array(z.object({ id: z.string(), total: z.number() })) }),
  scopes: ["invoices:read"],
  tags: ["read-only"],
  execute: async (_input, ctx) => invoices.list({ tenantId: ctx.tenantId }),
});
```

## 3. Mount the MCP endpoint

### Web-standard / Next.js

```ts
// app/api/mcp/route.ts
import { createFetchHandler } from "gapmcp-server";
import { apiKeyAuth } from "gapmcp-auth";
import { createRegistry } from "gapmcp-core";
import { createInvoice, listInvoices } from "@/actions";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const handler = createFetchHandler({
  registry: createRegistry(createInvoice, listInvoices),
  auth: apiKeyAuth({
    keys: [{ key: process.env.GAP_TOKEN!, principal: { id: "demo", scopes: ["*"] } }],
  }),
});

export { handler as GET, handler as POST, handler as DELETE };
```

### Node / Hono / Express

```ts
import { createServer } from "node:http";
import { createGapServer } from "gapmcp-server";
import { createRegistry } from "gapmcp-core";
import { actions } from "./actions";

const gap = createGapServer({
  registry: createRegistry(...actions),
  auth: /* apiKeyAuth or jwtAuth */ undefined,
  baseUrl: "http://127.0.0.1:4400",
});

createServer((req, res) => void gap.handleNode(req, res)).listen(4400);
```

The endpoint is `POST /mcp` (plus `GET` for SSE and `DELETE` for session
cleanup). Protected-resource metadata lives at
`/.well-known/oauth-protected-resource`.

## 4. Connect a client

### Claude Code / Claude Desktop

```json
{
  "mcpServers": {
    "my-app": {
      "command": "npx",
      "args": ["-y", "gapmcp-cli", "serve", "./actions.ts", "--stdio"]
    }
  }
}
```

### Cursor

Use the same `command`/`args` shape in Cursor's MCP settings, or point it at
your HTTP endpoint:

```json
{ "mcpServers": { "my-app": { "url": "http://127.0.0.1:4400/mcp" } } }
```

## 5. Inspect and test

```bash
npx gap inspect ./actions.ts
```

The inspector shows every tool, its risk and scopes, a live playground that
uses the real MCP pipeline, the call log and pending approvals. Bind it to
`127.0.0.1`; it is a development surface.

```bash
npx gap lint ./actions.ts
npx gap evals ./evals.json --registry ./actions.ts --planner mock
```

## Next

- [Actions](./actions.md) — the contract in detail.
- [Auth](./auth.md) — delegated identity, scopes and approvals.
- [Policy](./policy.md) — limits, confirmation and redaction.
- [Fallback ladder](./fallback.md) — semantic DOM and human handoff.
- [Evals](./evals.md) — prove the agent picks the right tool.
