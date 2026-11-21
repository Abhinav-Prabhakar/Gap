# gapmcp-policy

Policy-as-code for agent actions.

```ts
import { GapPolicy, parsePolicy } from "gapmcp-policy";

const policy = new GapPolicy(parsePolicy(JSON.stringify({
  version: 1,
  default: "allow",
  rules: [
    { tools: ["orders.refund"], maxAmount: 500, amountPaths: ["amount"] },
    { tools: ["invoices.send"], confirm: true },
    { tools: ["admin.*"], deny: true },
  ],
})));
```

Limits, confirmations, dry-run and nested redaction paths (`cards[].number`).

Part of [Gap](https://github.com/Abhinav-Prabhakar/Gap) — typed actions for agents. MIT licensed.
