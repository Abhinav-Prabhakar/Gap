# Demo — in-memory invoicing

A runnable Gap app with eight actions, two API keys, policy limits, a
confirmation-gated send, a background export, receipts, undo, audit and a UI
binding.

```bash
pnpm install
pnpm demo
```

```text
Gap demo invoicing app
  MCP        http://127.0.0.1:4400/mcp
  Info       http://127.0.0.1:4400/info
  Owner key  demo-key
  Reader key demo-readonly-key
```

```bash
curl -s http://127.0.0.1:4400/info | jq
```

Inspect the same registry in the UI:

```bash
pnpm gap inspect examples/demo/src/actions.ts --token demo-key
```

## Try the safety rail

1. Connect with the **read-only** key. `invoices.create`, `invoices.send` and
   `invoices.delete` disappear from `tools/list` because the principal lacks
   their scopes.
2. Create an invoice with the owner key.
3. Call `invoices.send`. It returns `approval_required` with an approval id.
4. Approve it in the inspector, then retry the same call. It executes.
5. Call `gap.receipts.get` and `gap.undo` to reverse a draft deletion.
6. Call `exports.invoices` and poll `gap.tasks.get`.

## Layout

| File | What it shows |
| --- | --- |
| `src/actions.ts` | Action definitions, Zod schemas, risk, scopes, UI binding, undo, task |
| `src/server.ts` | Auth, policy, approvals, audit, handoff, MCP endpoint |
| `policy.json` | Limits, confirmation and redaction |

Everything is in memory and resets on restart. Replace the handler bodies with
your services; the contract above them does not change.
