# Policy

Policy is evaluated before validation and execution, on every call. It is the
place for blast-radius limits and confirmations that should not live in
individual actions.

```json
{
  "version": 1,
  "default": "allow",
  "rules": [
    {
      "tools": ["invoices.create"],
      "maxAmount": 10000,
      "amountPaths": ["unitPrice"],
      "maxArrayLength": 20,
      "arrayPaths": ["lineItems"],
      "reason": "Invoice lines are capped for agent callers."
    },
    {
      "tools": ["invoices.send"],
      "confirm": true,
      "reason": "Sending email is externally visible."
    },
    {
      "tools": ["admin.*"],
      "deny": true,
      "reason": "Admin tools are not exposed to agents."
    },
    {
      "tools": ["exports.*"],
      "dryRun": true
    },
    {
      "tools": ["customers.*"],
      "redact": ["email", "phone"]
    }
  ]
}
```

```ts
import { readFileSync } from "node:fs";
import { GapPolicy, parsePolicy } from "gapmcp-policy";

const policy = new GapPolicy(parsePolicy(readFileSync("gap.policy.json", "utf8")));
```

## Matching

- `tools`: exact (`invoices.send`), namespace wildcard (`invoices.*`) or `*`.
- `scopes`: rule only applies when the principal has all listed scopes.
- Rules are evaluated in order.
- **Deny wins.** If any matching rule denies, the call is denied.
- Otherwise any matching `confirm` requires approval.
- Otherwise the call is allowed (or denied when `default: "deny"`).

## Limits

`maxAmount` checks any numeric value at `amountPaths`
(default: `amount`, `total`, `value`, `price`, `cost`) anywhere in the argument
tree, including arrays. It denies when a single value exceeds the cap.

`maxArrayLength` checks arrays at `arrayPaths` (dot/bracket paths), or every
array when `arrayPaths` is omitted.

```ts
{
  tools: ["orders.refund"],
  maxAmount: 500,
  amountPaths: ["amount"],
  maxArrayLength: 100,
  arrayPaths: ["items"]
}
```

Limits are a floor, not a substitute for server-side authorization. Keep the
same checks in your domain layer.

## Redaction

`redact` removes fields from the result before it reaches the model, audit
result hash or inspector:

```json
{ "tools": ["customers.*"], "redact": ["email", "cards[].number"] }
```

Paths support dot notation, numeric indexes and `[]`/`[*]` wildcards. Values
become `[REDACTED]`; the source object is not mutated.

## Dry run

`dryRun` sets `ctx.dryRun = true`. Actions must honour it:

```ts
execute: async (input, ctx) => {
  const draft = buildInvoice(input);
  if (!ctx.dryRun) await db.invoices.insert(draft);
  return draft;
}
```

The audit decision is `dry_run` and no external effect should occur.

## Programmatic policies

Use the JSON DSL when possible. For custom logic, implement `PolicyEngine`:

```ts
import type { PolicyEngine } from "gapmcp-core";

export const policy: PolicyEngine = {
  evaluate({ action, args, ctx }) {
    if (action.name === "payments.refund" && !ctx.scopes.includes("payments:refund")) {
      return { decision: "deny", code: "SCOPE", reason: "Refund scope missing." };
    }
    return { decision: "allow" };
  },
};
```

Return `confirm` to park the call for approval, `deny` to block, or `allow`.
Never throw for a normal decision; return a decision with a reason so it lands in
the audit trail.
