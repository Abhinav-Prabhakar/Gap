# gapmcp-core

The action contract, registry, schema conversion and shared types.

```bash
npm install gapmcp-core zod
```

```ts
import { defineAction } from "gapmcp-core";
import { z } from "zod";

export const createInvoice = defineAction({
  name: "invoices.create",
  description: "Create a draft invoice. Does not send it.",
  input: z.object({
    customerId: z.string().describe("Customer id, e.g. cus_8f2."),
    total: z.number().positive().describe("Total in USD."),
  }),
  output: z.object({ id: z.string(), total: z.number() }),
  scopes: ["invoices:write"],
  risk: "medium",
  idempotent: true,
  execute: async (input, ctx) => invoices.create({ ...input, actor: ctx.principal.id }),
});
```

Also exports `ActionRegistry`, `defineSkill` (compound actions), `searchActions`, schema helpers, `GapError` and redaction/canonicalization utilities.

Part of [Gap](https://github.com/Abhinav-Prabhakar/Gap) — typed actions for agents. MIT licensed.
