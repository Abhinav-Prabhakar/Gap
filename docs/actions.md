# Actions

An action is the unit of agent capability. It is not an HTTP route. Routes are
shaped by transport concerns; actions are shaped by *intent* and by the
permission and blast radius of a single meaningful operation.

```ts
export const refundOrder = defineAction({
  name: "orders.refund",
  description:
    "Refund a paid order, in full or in part. Creates a refund and emails the customer. Requires approval above $100.",
  input: z.object({
    orderId: z.string().describe("Order id, e.g. ord_9f2."),
    amount: z.number().positive().describe("Refund amount in USD."),
    reason: z.enum(["damaged", "late", "duplicate", "goodwill"]).describe("Refund reason."),
  }),
  output: z.object({ refundId: z.string(), status: z.enum(["pending", "succeeded"]) }),
  scopes: ["orders:write", "payments:refund"],
  risk: "high",
  idempotent: true,
  confirm: (input) => input.amount > 100,
  execute: async (input, ctx) => refunds.create({ ...input, actor: ctx.principal.id }),
});
```

## Required fields

| Field | Why it exists |
| --- | --- |
| `name` | Stable dot-namespaced id. This is what the model calls. |
| `description` | **Model-facing.** Say what it does, what it does *not* do, and its side effects. |
| `execute` | The application function. Receives validated input and a delegated context. |

Everything else is optional but strongly recommended.

## Description rules

Tool selection is a retrieval problem. Descriptions are the index.

- Lead with the verb and the object: "Create a draft invoice…".
- State side effects and external visibility: "Emails the customer."
- State what it does *not* do: "Does not send it."
- Mention prerequisites and valid states.
- Include units, formats and id constraints in field `.describe()` calls.
- Avoid marketing language and implementation details.
- Say when to prefer a sibling tool: "Use `invoices.list` first to find the id."

`gap lint` flags missing, short, long and ambiguous descriptions, and
undescribed input fields.

## Naming

Use `namespace.verb` or `namespace.object.verb`:

```
customers.list
invoices.create
invoices.send
reports.revenue
admin.users.suspend
```

Namespace by domain, not by HTTP resource. Keep it under 64 characters. Version
with the `version` field rather than renaming; mark old actions `deprecated`.

## Input and output schemas

Zod 4 or plain JSON Schema both work. Zod gives handler inference; JSON Schema
is useful for generated actions.

- Input must be an object schema (MCP requirement).
- `output` becomes `structuredContent` and the tool's `outputSchema`.
- Describe every field. `gap lint` measures coverage.
- Prefer enums and constraints over prose.
- Keep arrays bounded with `.max()`; agents will find the limit.
- Never put secrets in schemas, examples or defaults.

## Risk and confirmation

| Risk | Typical actions |
| --- | --- |
| `low` | reads, drafts, previews |
| `medium` | creating records, internal notifications |
| `high` | sending externally, charging, changing access |
| `critical` | deleting, refunding, transferring money |

`confirm: true` parks the call for human approval. Use a function for
conditional approval:

```ts
confirm: (input) => input.amount > 100
```

High-risk actions without confirmation produce a lint warning. Approval grants
are bound to a hash of the exact arguments, so a retry with different arguments
needs a new approval.

## Scopes

Actions declare OAuth-style scopes (`invoices:write`). Tool discovery is
scope-filtered: an agent never sees a tool its principal cannot call. This is
both a safety property and a context-budget win.

```ts
scopes: ["invoices:read"]
```

Wildcards are supported when granting (`invoices:*`), not when declaring.

## Idempotency

Set `idempotent: true` for actions that are safe to retry. The server derives a
key from principal + action + canonical arguments (or accepts an explicit
`idempotencyKey` in `_meta`) and replays the stored result for 10 minutes.
Concurrent duplicates share one in-flight execution.

## Tasks

Long-running actions can return immediately:

```ts
task: true
```

The call returns `{ taskId, status: "working" }`; poll `gap.tasks.get` and stop
with `gap.tasks.cancel`. The action receives an abort signal it should honour.

## Undo and receipts

Every successful call gets a receipt. If the action defines `undo`, the
`gap.undo` tool can reverse it within the receipt window:

```ts
undo: async (result, input, ctx) => {
  await invoices.restore(input.id);
}
```

Undo is best-effort. Prefer soft deletes and explicit compensating actions.

## UI binding

The same action can describe how a human or browser agent performs it:

```ts
ui: {
  route: "/invoices/new",
  action: "invoices.create",
  fields: { customerId: "#customer", total: "#total" },
  submit: "#create-invoice",
  result: "#invoice-id",
}
```

`gap dom` compiles this into a manifest and a dependency-free runtime; see
[the fallback ladder](./fallback.md).

## Compound skills

When a workflow is deterministic, do not make the model orchestrate five calls.
Compose actions into one tool:

```ts
import { defineSkill } from "gapmcp-core";

export const invoiceCustomer = defineSkill({
  name: "customers.invoice",
  description: "Find a customer by name and create a draft invoice for them.",
  input: z.object({ customer: z.string(), total: z.number().positive() }),
  output: z.object({ invoiceId: z.string() }),
  uses: [findCustomer, createInvoice],
  execute: async ({ customer, total }, _ctx, run) => {
    const found = await run<{ id: string }>(findCustomer, { query: customer });
    const invoice = await run<{ id: string }>(createInvoice, { customerId: found.id, total });
    return { invoiceId: invoice.id };
  },
});
```

`defineSkill` unions the scopes of every action it uses, so composition cannot
bypass discovery or policy. The child actions run with the same context
(principal, dry-run, signal, approval) as the parent.

## Progressive disclosure

A large catalog makes tool selection worse. `searchActions` ranks actions by
name, tags and description, filtered to the caller's scopes:

```ts
import { searchActions } from "gapmcp-core";

const matches = searchActions(registry, "refund a charge", {
  scopes: ctx.scopes,
  limit: 10,
});
```

The server exposes the same ranking as `gap.search` once a principal can see
more than 12 actions. The results include names, descriptions, risk and scopes,
so the model can call the right tool without every schema in context.

## Contract diff

Treat the tool surface as an API. `diffRegistries` detects breaking changes
before release:

```ts
import { diffRegistries } from "gapmcp-core";

const diff = diffRegistries(previousActions, nextActions);
if (!diff.compatible) {
  console.error(diff.breaking);
  process.exit(1);
}
```

Removed actions, removed or newly required input fields, changed field types,
narrowed enums and added scopes are breaking. Description, risk and deprecation
changes are reported without failing.

## Context

```ts
interface ActionContext {
  principal: Principal;   // delegated user or service
  scopes: string[];
  tenantId?: string;
  dryRun: boolean;
  idempotencyKey?: string;
  approval?: ApprovalGrant;
  signal: AbortSignal;    // honour this in every await
  traceId: string;
  logger: Logger;
  request?: unknown;      // adapter request, if needed
  services?: Record<string, unknown>;
}
```

Treat `ctx.principal` as the source of truth for authorization inside the
action. A valid MCP call is not a substitute for checking that this user may
touch this row.
