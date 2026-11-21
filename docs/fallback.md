# The fallback ladder

Computer-use is the universal fallback, not the interface. Gap's bet is that
the same *semantic action* should be executable at the cheapest reliable layer:

| Tier | Mechanism | When | Cost |
| --- | --- | --- | --- |
| 0 | Native action over MCP | Default | milliseconds |
| 1 | Semantic DOM (`data-gap-action`) | App has UI but no action | seconds |
| 2 | Accessibility tree | Third-party or uninstrumented UI | seconds |
| 3 | Pixels / vision | Last resort | seconds–minutes |

An action is defined once. The native executor is `execute`; the DOM executor
is compiled from `ui`. A browser agent can then invoke `invoices.create` by
intent, with arguments validated by the same schema, instead of hunting for a
button labelled "New".

## 1. Describe the UI on the action

```ts
export const createInvoice = defineAction({
  // ...
  ui: {
    route: "/invoices/new",
    action: "invoices.create",
    fields: {
      customerId: "#customer",
      total: "#total",
    },
    submit: "#create-invoice",
    result: "#invoice-id",
    waitFor: "#invoice-id",
  },
});
```

## 2. Compile the manifest and runtime

```bash
gap dom ./actions.ts --out gap.dom.json --runtime gap.dom.js
```

The manifest lists every action that has a UI binding, with scopes and risk. The
runtime is a dependency-free IIFE:

```html
<script src="/gap.dom.js"></script>
<script>
  await Gap.call("invoices.create", {
    customerId: "cus_ada",
    total: 4200,
  });
</script>
```

The runtime finds `[data-gap-action="invoices.create"]`, fills the bound fields
(using native setters so React sees the change), clicks submit, waits for the
result selector, and returns its text. It never types credentials and never
guesses at layout.

## 3. Annotate the real UI

```html
<form data-gap-action="invoices.create">
  <select id="customer"></select>
  <input id="total" />
  <button id="create-invoice">Create</button>
  <output id="invoice-id"></output>
</form>
```

The annotation is inert for humans and useful for agents. It also gives your UI
tests a stable semantic handle.

## 4. Human handoff

When an agent cannot finish — missing information, a CAPTCHA, a judgement call —
hand the exact state to a human and resume:

```ts
const url = await createHandoffUrl({
  baseUrl: "https://app.example.com",
  action: "invoices.create",
  args: { customerId: "cus_ada", total: 4200 },
  secret: process.env.HANDOFF_SECRET!,
  path: "/invoices/new",
});
```

The link carries a signed, expiring `gap_state` token with the draft. The app
verifies it, pre-fills the form, and the human finishes. The token is bound to
the action and arguments, so the page cannot be tricked into restoring a
different payload.

## Recording a human once

A useful workflow we recommend:

1. Instrument the flow with `data-gap-action`.
2. Record a human completing it (Playwright trace or a small recorder).
3. Turn the trace into an action stub: selectors become `ui.fields`, the final
   screen becomes `ui.result`.
4. Replace `execute` with a real application service when ready.

The DOM path buys you coverage before the native path exists; the native path
then buys speed and determinism without changing the contract.

## What this is not

- It is not a promise that every UI can be automated. Tier 2/3 remain.
- It does not bypass auth. The browser session still needs the user's login.
- It does not make destructive actions safe on its own. Use `risk`,
  `confirm`, policy limits and approvals.
